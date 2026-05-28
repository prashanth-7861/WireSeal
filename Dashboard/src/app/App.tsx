import { useEffect } from "react";
import { RouterProvider } from "react-router";
import { Toaster } from "sonner";
import { router } from "./routes";
import { api } from "./api";

export default function App() {
  useEffect(() => {
    const handleRejection = (e: PromiseRejectionEvent) => {
      console.error("Unhandled promise rejection:", e.reason);
    };
    window.addEventListener("unhandledrejection", handleRejection);

    const handleError = (e: ErrorEvent) => {
      console.error("Unhandled error:", e.error ?? e.message);
      const { message, filename, lineno, error } = e;
      api.logClientError({
        message: error?.stack ? `${message}\n${error.stack}` : message,
        url: filename,
        line: lineno,
      }).catch(() => {});
    };
    window.addEventListener("error", handleError);

    return () => {
      window.removeEventListener("unhandledrejection", handleRejection);
      window.removeEventListener("error", handleError);
    };
  }, []);

  return (
    <>
      <Toaster position="bottom-right" richColors />
      <RouterProvider router={router} />
    </>
  );
}
