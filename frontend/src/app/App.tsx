import { useState } from "react";
import { RouterProvider, createBrowserRouter } from "react-router";

import { createQueryClient } from "../lib/queryClient";
import { AppProviders } from "./providers";
import { routes } from "./routes";

const router = createBrowserRouter(routes);

export function App() {
  const [queryClient] = useState(createQueryClient);
  return (
    <AppProviders client={queryClient}>
      <RouterProvider router={router} />
    </AppProviders>
  );
}
