# Sprint 7 usability validation protocol

This protocol records the human validation required by TEST-5. Automated tests
cover keyboard paths, state transitions, errors, and timing instrumentation, but
they do not replace observation of real participants.

## Participants

Recruit at least five adults who did not implement the feature. Include at least
one keyboard-only participant and, where available, one screen-reader user. Do
not ask participants to use real passwords or personal vault data.

## Tasks

1. Unlock the training vault and find an entry by keyboard.
2. Copy a training password, observe the countdown, and clear it manually.
3. Change the auto-lock timeout and security profile, then explain the warning.
4. Minimize to the tray, restore the window, and lock from the tray menu.
5. Trigger panic mode with the hotkey and recover with the training password.

## Measurements

For each participant record task duration, completion, errors, assistance, and a
one-to-five confidence score. Record only anonymous participant codes. The
acceptance target is at least 90% task completion, no critical security errors,
and a median confidence score of four or higher.

| Participant | T1 | T2 | T3 | T4 | T5 | Errors | Assistance | Confidence |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P01 |  |  |  |  |  |  |  |  |
| P02 |  |  |  |  |  |  |  |  |
| P03 |  |  |  |  |  |  |  |  |
| P04 |  |  |  |  |  |  |  |  |
| P05 |  |  |  |  |  |  |  |  |

## Reporting

Keep the completed sheet with the course submission. Summarize recurring errors,
the median time for each task, and any changes made after the sessions. An empty
table means the external human study has not yet been conducted.
