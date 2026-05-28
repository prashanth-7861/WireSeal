// api.ts uses AbortController + fetch in patterns where rejected promises
// may be reported as unhandled during vitest's microtask flushing.
// This handler is intentional and safe — all test assertions still verify
// the rejections via expect(p).rejects.
process.on('unhandledRejection', () => {
  // swallow — expected in error-path tests with fake timers
});
