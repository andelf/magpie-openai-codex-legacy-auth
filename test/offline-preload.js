// The real host captures this fetch at startup. No vendor traffic is allowed.
globalThis.fetch = async () => { throw new Error("Offline host test forbids network access") }
