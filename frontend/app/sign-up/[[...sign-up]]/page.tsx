import { SignUp } from "@clerk/nextjs";

import { AuthPageShell } from "@/components/auth-page-shell";
import { clerkAppearance } from "@/lib/clerk-appearance";

export default function SignUpPage() {
  return (
    <AuthPageShell
      title="Create your BoxAI account"
      description="Sign up to unlock the protected analyst workflow. BoxAI keeps scanning, remediation, and report review inside one controlled environment."
      alternateHref="/sign-in"
      alternateLabel="Already registered? Log in"
    >
      <SignUp
        path="/sign-up"
        routing="path"
        signInUrl="/sign-in"
        fallbackRedirectUrl="/"
        appearance={clerkAppearance}
      />
    </AuthPageShell>
  );
}