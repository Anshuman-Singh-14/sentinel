import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach } from "vitest";

// findBy*/waitFor default to 1 s. Under a full parallel run in Docker on a
// slow host, first renders (route chunk + several mocked fetches) can take
// longer, which made unrelated tests fail at random. A real hang still fails.
configure({ asyncUtilTimeout: 5000 });

afterEach(() => {
  cleanup();
});
