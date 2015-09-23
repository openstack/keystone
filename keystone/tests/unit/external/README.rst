This directory contains interface tests for external libraries. The goal
is not to test every possible path through a library's code and get 100%
coverage. It's to give us a level of confidence that their general interface
remains the same through version upgrades.

This gives us a place to put these tests without having to litter our
own tests with assertions that are not directly related to the code
under test. The expectations for the external library are all in one
place so it makes it easier for us to find out what they are.
