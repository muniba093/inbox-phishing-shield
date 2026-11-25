import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { ArrowLeft, Lock, Shield } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { supabase } from "@/integrations/supabase/client";
import { PasswordSchema } from "@/lib/auth.schema";

export const Route = createFileRoute("/reset-password")({
  staticData: { sitemap: false },
  head: () => ({
    meta: [
      { title: "Choose a new password · PhishGuard AI" },
      { name: "description", content: "Set a new password for your PhishGuard AI account." },
      { property: "og:title", content: "Choose a new password · PhishGuard AI" },
      { property: "og:description", content: "Securely update your PhishGuard AI account password." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const navigate = useNavigate();
  const [linkChecked, setLinkChecked] = useState(false);
  const [recoveryLink, setRecoveryLink] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const hashParams = new URLSearchParams(window.location.hash.slice(1));
    setRecoveryLink(hashParams.get("type") === "recovery");
    setLinkChecked(true);
    const { data: authListener } = supabase.auth.onAuthStateChange((event) => {
      if (event === "PASSWORD_RECOVERY") setRecoveryLink(true);
    });
    return () => authListener.subscription.unsubscribe();
  }, []);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!PasswordSchema.safeParse(password).success) {
      toast.error("Use at least 6 characters for your password.");
      return;
    }
    if (password !== confirmation) {
      toast.error("The passwords do not match.");
      return;
    }

    setSaving(true);
    try {
      const { error } = await supabase.auth.updateUser({ password });
      if (error) throw error;
      toast.success("Password updated.");
      await navigate({ to: "/" });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not update your password.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-16">
      <section className="glass w-full max-w-md rounded-lg p-6 sm:p-8">
        <Link to="/" className="mb-8 flex items-center justify-center gap-2">
          <Shield className="size-8 text-primary" />
          <span className="text-xl font-bold">PhishGuard <span className="text-primary">AI</span></span>
        </Link>

        {!linkChecked ? (
          <p role="status" className="text-center text-sm text-muted-foreground">Checking your link…</p>
        ) : recoveryLink ? (
          <>
            <h1 className="text-2xl font-bold">Choose a new password</h1>
            <p className="mt-1 text-sm text-muted-foreground">Use at least 6 characters.</p>
            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <label className="block">
                <span className="mb-1.5 flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                  <Lock className="size-3.5" /> New password
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  minLength={6}
                  required
                  className="w-full rounded-md border border-border bg-background/40 px-4 py-2.5 text-sm placeholder:text-muted-foreground/60 focus:outline-none focus:ring-2 focus:ring-ring/50"
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs uppercase tracking-wider text-muted-foreground">Confirm password</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  minLength={6}
                  required
                  className="w-full rounded-md border border-border bg-background/40 px-4 py-2.5 text-sm placeholder:text-muted-foreground/60 focus:outline-none focus:ring-2 focus:ring-ring/50"
                />
              </label>
              <Button type="submit" disabled={saving} className="h-11 w-full font-semibold">
                {saving ? "Saving…" : "Save new password"}
              </Button>
            </form>
          </>
        ) : (
          <>
            <h1 className="text-2xl font-bold">Password link unavailable</h1>
            <p className="mt-2 text-sm text-muted-foreground">Request a new link from the sign-in page and open it from your email.</p>
            <Button asChild variant="outline" className="mt-6 w-full">
              <Link to="/auth"><ArrowLeft /> Back to sign in</Link>
            </Button>
          </>
        )}
      </section>
    </main>
  );
}