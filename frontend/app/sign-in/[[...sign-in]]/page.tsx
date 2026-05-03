import { SignIn } from "@clerk/nextjs";

import { AuthPageShell } from "@/components/auth-page-shell";
import { clerkAppearance } from "@/lib/clerk-appearance";

export default function SignInPage() {
  return (
    <AuthPageShell
      title="Return to the sealed workspace"
      description="Authenticate before entering BoxAI. Once inside, the scan workspace, findings, and reports stay behind a signed-in boundary."
      alternateHref="/sign-up"
      alternateLabel="Need an account? Create one"
    >
      <SignIn
        path="/sign-in"
        routing="path"
        signUpUrl="/sign-up"
        fallbackRedirectUrl="/"
        appearance={clerkAppearance}
      />
    </AuthPageShell>
  );
}