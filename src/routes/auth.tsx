import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ArrowRight, Globe2, Loader2, Lock, Mail, Shield } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { lovable } from "@/integrations/lovable/index";
import { supabase } from "@/integrations/supabase/client";
import { PasswordSchema } from "@/lib/auth.schema";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in · PhishGuard AI" },
      { name: "description", content: "Sign in to PhishGuard AI to scan suspicious emails and review threat indicators." },
      { property: "og:title", content: "Sign in · PhishGuard AI" },
      { property: "og:description", content: "Secure access to PhishGuard AI email analysis." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [confirmationPending, setConfirmationPending] = useState(false);
  const [passwordResetSent, setPasswordResetSent] = useState(false);

  useEffect(() => {
    let active = true;
    const { data: authListener } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) void navigate({ to: "/" });
    });

    void supabase.auth.getUser().then(({ data }) => {
      if (active && data.user) void navigate({ to: "/" });
    });

    return () => {
      active = false;
      authListener.subscription.unsubscribe();
    };
  }, [navigate]);

  const handleEmail = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!email || !password) {
      toast.error("Enter your email and password.");
      return;
    }
    if (mode === "signup" && !PasswordSchema.safeParse(password).success) {
      toast.error("Use at least 6 characters for your password.");
      return;
    }

    setLoading(true);
    setConfirmationPending(false);
    try {
      if (mode === "signup") {
        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options: { emailRedirectTo: window.location.origin },
        });
        if (error) throw error;
        if (!data.session) {
          setConfirmationPending(true);
          toast.success("Check your email to confirm your account.");
          return;
        }
        toast.success("Account created.");
        await navigate({ to: "/" });
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        toast.success("Welcome back.");
        await navigate({ to: "/" });
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogle = async () => {
    setGoogleLoading(true);
    try {
      const result = await lovable.auth.signInWithOAuth("google", {
        redirect_uri: window.location.origin,
      });
      if (result.error) throw result.error;
      if (result.redirected) return;
      await navigate({ to: "/" });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Google sign-in failed.");
    } finally {
      setGoogleLoading(false);
    }
  };

  const handlePasswordReset = async () => {
    if (!email) {
      toast.error("Enter your email address first.");
      return;
    }
    setLoading(true);
    setPasswordResetSent(false);
    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/reset-password`,
      });
      if (error) throw error;
      setPasswordResetSent(true);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not send a reset link.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-16">
      <div className="w-full max-w-md">
        <Link to="/" className="mb-8 flex items-center justify-center gap-2">
          <Shield className="size-8 text-primary" />
          <span className="text-xl font-bold">PhishGuard <span className="text-primary">AI</span></span>
        </Link>

        <section className="glass rounded-lg p-6 sm:p-8">
          <h1 className="text-2xl font-bold">
            {mode === "signin" ? "Welcome back" : "Create your account"}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {mode === "signin" ? "Sign in to scan emails for phishing threats." : "Get AI-assisted phishing detection."}
          </p>

          <Button
            type="button"
            onClick={handleGoogle}
            disabled={googleLoading || loading}
            variant="outline"
            className="mt-6 h-11 w-full bg-background/40"
          >
            {googleLoading ? <Loader2 className="animate-spin" /> : <Globe2 />}
            Continue with Google
          </Button>

          <div className="my-6 flex items-center gap-3 text-xs uppercase tracking-wider text-muted-foreground">
            <div className="h-px flex-1 bg-border" />
            or
            <div className="h-px flex-1 bg-border" />
          </div>

          <form onSubmit={handleEmail} className="space-y-4">
            <label className="block">
              <span className="mb-1.5 flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                <Mail className="size-3.5" /> Email
              </span>
              <input
                type="email"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                className="w-full rounded-md border border-border bg-background/40 px-4 py-2.5 text-sm placeholder:text-muted-foreground/60 focus:outline-none focus:ring-2 focus:ring-ring/50"
                required
              />
            </label>

            <label className="block">
              <span className="mb-1.5 flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                <Lock className="size-3.5" /> Password
              </span>
              <input
                type="password"
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="••••••••"
                minLength={6}
                className="w-full rounded-md border border-border bg-background/40 px-4 py-2.5 text-sm placeholder:text-muted-foreground/60 focus:outline-none focus:ring-2 focus:ring-ring/50"
                required
              />
            </label>

            {mode === "signin" && (
              <div className="flex justify-end">
                <Button
                  type="button"
                  variant="link"
                  className="h-auto p-0 text-xs"
                  disabled={loading || googleLoading}
                  onClick={handlePasswordReset}
                >
                  Forgot password?
                </Button>
              </div>
            )}

            <Button type="submit" disabled={loading || googleLoading} className="h-11 w-full font-semibold">
              {loading ? <Loader2 className="animate-spin" /> : <>{mode === "signin" ? "Sign in" : "Create account"}<ArrowRight /></>}
            </Button>
          </form>

          {confirmationPending && (
            <p role="status" className="mt-4 rounded-md border border-safe/30 bg-safe/10 p-3 text-sm text-safe">
              Check your inbox and confirm your email before signing in.
            </p>
          )}
          {passwordResetSent && (
            <p role="status" className="mt-4 rounded-md border border-safe/30 bg-safe/10 p-3 text-sm text-safe">
              If an account uses this email, check your inbox for a password reset link.
            </p>
          )}

          <p className="mt-6 text-center text-sm text-muted-foreground">
            {mode === "signin" ? "New to PhishGuard?" : "Already have an account?"}{" "}
            <Button
              type="button"
              variant="link"
              className="h-auto p-0 font-semibold"
              onClick={() => {
                setMode(mode === "signin" ? "signup" : "signin");
                setConfirmationPending(false);
                setPasswordResetSent(false);
              }}
            >
              {mode === "signin" ? "Create one" : "Sign in"}
            </Button>
          </p>
        </section>

        <p className="mt-6 text-center text-xs text-muted-foreground">
          Email content is sent to Gemini for analysis and is not saved by PhishGuard.
        </p>
      </div>
    </main>
  );
}