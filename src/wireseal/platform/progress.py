"""Step progress reporter for WireSeal platform setup.

Locked output format per project decision:
  [N/TOTAL] Description... done
  [N/TOTAL] Description... FAILED
    Error: <message>
  Setup failed at step N/TOTAL. Steps 1-M completed successfully. Fix the error above and re-run.
"""


class Progress:
    """Reports numbered step progress to stdout.

    Usage::

        p = Progress(total=4)
        p.step("Installing WireGuard")
        # ... do work ...
        p.done()
        # Output: [1/4] Installing WireGuard... done

        p.step("Applying firewall rules")
        # ... work fails ...
        p.fail("nftables: command not found")
        # Output: [2/4] Applying firewall rules... FAILED
        #           Error: nftables: command not found
        #         Setup failed at step 2/4. Steps 1-1 completed successfully. Fix the error above and re-run.
    """

    def __init__(self, total: int) -> None:
        """Initialise the progress reporter.

        Args:
            total: Total number of steps in the setup sequence.
        """
        self.total = total
        self.current = 0

    def step(self, description: str) -> None:
        """Advance to the next step and print the step header.

        Prints: ``[N/TOTAL] Description...`` with no trailing newline so that
        :meth:`done` or :meth:`fail` can append their status on the same line.

        Args:
            description: Human-readable description of the step being performed.
        """
        self.current += 1
        print(f"[{self.current}/{self.total}] {description}...", end=" ", flush=True)

    def done(self) -> None:
        """Mark the current step as successful.

        Prints ``done`` on the same line as the step header.
        """
        print("done")

    def fail(self, error: str) -> None:
        """Mark the current step as failed and print diagnostic information.

        Prints ``FAILED`` on the same line as the step header, followed by
        the error detail and a recovery hint.

        Args:
            error: Human-readable description of the failure.
        """
        print("FAILED")
        print(f"  Error: {error}")
        completed = self.current - 1
        print(
            f"Setup failed at step {self.current}/{self.total}. "
            f"Steps 1-{completed} completed successfully. "
            "Fix the error above and re-run."
        )
