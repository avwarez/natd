natd - Windows x64 build (llvm-mingw, static: no DLL to install)

1. Extract the zip into any folder (no administrator account needed).
2. Double-click run-tests.cmd.
   If SmartScreen says "Windows protected your PC": More info -> Run anyway
   (the executables are not signed). Or: right-click the zip -> Properties -> Unblock,
   before extracting it.
3. At the end it must print "RESULT: all tests passed".
   Otherwise, send the .log files of the folder to the maintainer.

What the tests do:
  1/3 natd_tests.exe     library logic with simulated NATs (the same checks as on Linux and Wine)
  2/3 natd_io_tests.exe  Winsock adapter: send/receive, port in use, ICMP port unreachable
                         (WSAECONNRESET), close inside the callback, timeout
  3/3 natd_probe.exe + two natd_reflector.exe on loopback: full discovery with real sockets.
      Expected: predictability=Stable, behindNat=0, lifetimeMeasured=1.

The traffic stays on 127.0.0.x: the Windows firewall does not step in and no authorization
prompt appears.
