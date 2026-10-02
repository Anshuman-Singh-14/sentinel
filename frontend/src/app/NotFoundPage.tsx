import { Link, isRouteErrorResponse, useRouteError } from "react-router";

import { Card } from "../components/ui";
import { FullPageMessage } from "../features/auth/guards";

export function NotFoundPage() {
  return (
    <Card title="Not found">
      <p className="text-sm text-muted">There is nothing at this address.</p>
      <Link to="/" className="mt-3 inline-block text-sm text-accent underline">
        Back to the dashboard
      </Link>
    </Card>
  );
}

/**
 * Last-resort error screen for render errors. It deliberately shows no error
 * details: messages and stacks belong in the console, not on screen where they
 * may leak internals or untrusted data.
 */
export function RouteErrorPage() {
  const error = useRouteError();
  const notFound = isRouteErrorResponse(error) && error.status === 404;
  if (import.meta.env.DEV) console.error(error);
  return (
    <FullPageMessage>
      {notFound ? (
        <NotFoundPage />
      ) : (
        <Card title="Something went wrong">
          <p className="text-sm text-muted">
            The page hit an unexpected error. Reload to try again.
          </p>
          <a href="/" className="mt-3 inline-block text-sm text-accent underline">
            Back to the dashboard
          </a>
        </Card>
      )}
    </FullPageMessage>
  );
}
