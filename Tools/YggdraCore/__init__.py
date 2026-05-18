"""YggdraCore -- in-process 5G core stubs for AKA / AKMA flows.

Ships the AKMA Anchor Function (AAnF) state machine so the GUI
Command Center actions and the loopback HTTP mini-AUSF consume the
same in-memory store. The package is intentionally thin: no
networking, no persistence, no threads beyond the registration lock.
Anything that needs a real 5GC (UDM/AMF/SMF) is out of scope --
see docs/akma_overview.md for the BYO-Open5GS path.
"""
