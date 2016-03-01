# pyness
A Python library for interacting with a Nessus scanner and parsing scan results.

This package supports most of the useful API calls, including some wrapper
functions that are useful when automating tasks with a Nessus scanner. The
`Report` object can be used to parse a scan's Nessus v2 XML output that can be
downloaded with this library. A parsed scan can then be interacted with as a
normal python object instead of with the normal XML libraries.

This library has been through many iterations, most of which attempted to better
handle the errors associated with the username/password sessions required by
Nessus until one of the 6.x versions. Now that user API keys are permitted, the
authentication process is greatly simplified.

Missing functions can be easily added with the details from Nessus's built-in
API documentation. Just browse to <https://localhost:8834/api> if you have a
local scanner running.
