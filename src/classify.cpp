// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// Port allocation classifier.
//
// Input: external ports in the order the mappings were created (and, when
// known, the local ports that produced them). Output: the allocation pattern
// plus a confidence in [0, 1]. NatDiscovery asks for more samples while the
// confidence stays below AdvancedConfig::confidenceTarget (adaptive sampling).
//
// Decision order:
//   1. PortPreserving  external == local for most samples
//   2. Sequential      most steps equal one small constant delta
//   3. SequentialNoisy most steps small and with the same sign as the
//                      typical delta (other subscribers interleave)
//   4. RandomInBlock   no sequence, all samples inside a span <= maxBlockSize
//   5. RandomFull      no sequence, wider span
#include "natd/discovery.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <map>

namespace natd {
namespace {

// Largest step still considered "sequential with noise". Between two of our
// probes (a few ms apart) other subscribers of a busy CGNAT may take a few
// dozen ports; random allocation in a large range almost never produces a
// run of small same-sign steps.
constexpr int kNoisyMaxStep = 64;
// Largest step accepted as the constant delta of a clean sequence.
constexpr int kMaxSequentialDelta = 16;

int32_t signedStep(uint16_t from, uint16_t to) {
    return int32_t(int16_t(uint16_t(to - from)));   // wrap-around aware
}

// Smallest block that contains [lo, hi], aligned to its own size, among
// alignment * 2^k <= maxSize. Falls back to an alignment-rounded span.
PortBlock fitBlock(uint16_t lo, uint16_t hi, double estimate, uint32_t alignment, uint32_t maxSize) {
    if (alignment == 0) alignment = 1;
    for (uint32_t s = alignment; s <= maxSize && s <= 65536; s *= 2) {
        if (s < estimate) continue;
        uint32_t base = (uint32_t(lo) / s) * s;
        if (uint32_t(hi) < base + s) {
            uint32_t size = std::min<uint32_t>(s, 65536 - base);
            return {uint16_t(base), uint16_t(std::min<uint32_t>(size, 65535))};
        }
    }
    uint32_t base = (uint32_t(lo) / alignment) * alignment;
    uint32_t end = ((uint32_t(hi) + alignment) / alignment) * alignment;   // exclusive
    end = std::min<uint32_t>(end, 65536);
    return {uint16_t(base), uint16_t(std::min<uint32_t>(end - base, 65535))};
}

} // namespace

AllocationInfo classifyAllocation(const std::vector<uint16_t>& ports,
                                  const std::vector<uint16_t>& localPorts,
                                  const AdvancedConfig& cfg) {
    AllocationInfo out;
    const int n = int(ports.size());
    out.samples = n;
    if (n < 2) return out;   // Unknown, confidence 0

    const double target = cfg.confidenceTarget;

    // 1. Port preservation
    if (localPorts.size() == ports.size()) {
        int same = 0;
        for (int i = 0; i < n; ++i) same += ports[i] == localPorts[i];
        double frac = double(same) / n;
        if (frac >= target) {
            out.pattern = AllocationPattern::PortPreserving;
            out.confidence = frac;
            return out;
        }
    }

    // Steps between consecutive allocations
    std::vector<int32_t> steps;
    steps.reserve(n - 1);
    for (int i = 1; i < n; ++i) steps.push_back(signedStep(ports[i - 1], ports[i]));
    const int m = int(steps.size());

    // Most frequent non-zero step (mode); zero steps mean a reused mapping.
    std::map<int32_t, int> freq;
    for (int32_t s : steps) if (s != 0) ++freq[s];
    int32_t mode = 0;
    int modeCount = 0;
    for (auto& [s, c] : freq)
        if (c > modeCount || (c == modeCount && std::abs(s) < std::abs(mode))) { mode = s; modeCount = c; }

    auto fillJitter = [&](int32_t ref) {
        double acc = 0;
        for (int32_t s : steps) acc += double(s - ref) * double(s - ref);
        out.jitter = std::sqrt(acc / m);
    };

    // 2. Clean sequence
    double seqScore = 0;
    if (mode != 0 && std::abs(mode) <= kMaxSequentialDelta) {
        seqScore = double(modeCount) / m;
        if (seqScore >= target) {
            out.pattern = AllocationPattern::Sequential;
            out.delta = mode;
            out.confidence = seqScore;
            fillJitter(mode);
            return out;
        }
    }

    // 3. Noisy sequence: small steps sharing one sign
    int pos = 0, neg = 0;
    for (int32_t s : steps) {
        if (s > 0 && s <= kNoisyMaxStep) ++pos;
        if (s < 0 && -s <= kNoisyMaxStep) ++neg;
    }
    const int dir = pos >= neg ? 1 : -1;
    const double noisyScore = double(std::max(pos, neg)) / m;
    if (noisyScore >= target) {
        std::vector<int32_t> good;
        for (int32_t s : steps) if (s * dir > 0 && std::abs(s) <= kNoisyMaxStep) good.push_back(s);
        std::nth_element(good.begin(), good.begin() + good.size() / 2, good.end());
        out.pattern = AllocationPattern::SequentialNoisy;
        out.delta = good[good.size() / 2];
        out.confidence = noisyScore;
        fillJitter(out.delta);
        return out;
    }
    seqScore = std::max(seqScore, noisyScore);

    // 4/5. Random. Span measured on the circle would hide a block that
    // straddles 65535->0; real allocators do not do that, so use plain min/max.
    auto [lo, hi] = std::minmax_element(ports.begin(), ports.end());
    const uint32_t span = uint32_t(*hi) - uint32_t(*lo) + 1;

    // Evidence of randomness grows with the sample count: with few samples a
    // noisy sequence and a random draw look alike. 1 - 2^(-n/4): n=8 -> 0.75,
    // n=16 -> 0.94, n=32 -> 0.996. Penalised by how sequential the data looked.
    const double sizeFactor = 1.0 - std::pow(2.0, -double(n) / 4.0);
    out.confidence = sizeFactor * (1.0 - seqScore);

    if (span <= cfg.maxBlockSize) {
        // Unbiased estimate of a uniform range from its sample span.
        const double estimate = double(span) * double(n + 1) / double(n - 1);
        out.pattern = AllocationPattern::RandomInBlock;
        out.block = fitBlock(*lo, *hi, estimate, cfg.blockAlignment, cfg.maxBlockSize);
    } else {
        out.pattern = AllocationPattern::RandomFull;
    }
    return out;
}

const char* toString(Predictability p) {
    switch (p) {
    case Predictability::Stable: return "Stable";
    case Predictability::Predictable: return "Predictable";
    case Predictability::Bounded: return "Bounded";
    case Predictability::Unpredictable: return "Unpredictable";
    case Predictability::UdpBlocked: return "UdpBlocked";
    case Predictability::Inconclusive: return "Inconclusive";
    }
    return "?";
}

const char* toString(MappingBehavior b) {
    switch (b) {
    case MappingBehavior::Unknown: return "Unknown";
    case MappingBehavior::EndpointIndependent: return "EndpointIndependent";
    case MappingBehavior::AddressDependent: return "AddressDependent";
    case MappingBehavior::AddressPortDependent: return "AddressPortDependent";
    }
    return "?";
}

const char* toString(FilteringBehavior b) {
    switch (b) {
    case FilteringBehavior::Unknown: return "Unknown";
    case FilteringBehavior::EndpointIndependent: return "EndpointIndependent";
    case FilteringBehavior::AddressDependent: return "AddressDependent";
    case FilteringBehavior::AddressPortDependent: return "AddressPortDependent";
    }
    return "?";
}

const char* toString(AllocationPattern a) {
    switch (a) {
    case AllocationPattern::Unknown: return "Unknown";
    case AllocationPattern::PortPreserving: return "PortPreserving";
    case AllocationPattern::Sequential: return "Sequential";
    case AllocationPattern::SequentialNoisy: return "SequentialNoisy";
    case AllocationPattern::RandomInBlock: return "RandomInBlock";
    case AllocationPattern::RandomFull: return "RandomFull";
    }
    return "?";
}

const char* toString(QuickCheckResult r) {
    switch (r) {
    case QuickCheckResult::Pending: return "Pending";
    case QuickCheckResult::Valid: return "Valid";
    case QuickCheckResult::Changed: return "Changed";
    case QuickCheckResult::Unreachable: return "Unreachable";
    }
    return "?";
}

const char* toString(HairpinBehavior h) {
    switch (h) {
    case HairpinBehavior::Unknown: return "Unknown";
    case HairpinBehavior::None: return "None";
    case HairpinBehavior::External: return "External";
    case HairpinBehavior::Internal: return "Internal";
    }
    return "?";
}

} // namespace natd
