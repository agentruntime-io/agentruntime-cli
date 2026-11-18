package cli

// `agentruntime login --github-actions`: sign a GitHub Actions job in without a stored key.
//
// A job that has `permissions: id-token: write` can ask GitHub for an identity token, a signed statement of which
// repository, branch and workflow is running. The CLI asks for one, hands it to the API together with the id of a CI
// trust a workspace admin made for that repository, and gets back a short-lived access key (the trust sets how long)
// that can only fetch the secrets the trust lists. The key goes into the profile with its expiry, or, with
// --export-env, into the file GitHub reads to set the environment of the job's next steps.
//
// Three values are secrets here and none of them is ever printed: the request token GitHub gives the job, the
// identity token, and the access key. The one exception is the line `::add-mask::<key>` that --export-env prints
// first, which is how a job tells GitHub to hide a value from its logs.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentruntime-io/agentruntime-cli/internal/bffclient"
	"github.com/agentruntime-io/agentruntime-cli/internal/config"
	"github.com/agentruntime-io/agentruntime-cli/internal/ghactions"
)

const githubActionsLoginLong = `--github-actions signs a GitHub Actions job in without a stored key. The job asks
GitHub for an identity token (it says which repository, branch and workflow is
running), the CLI gives it to the API with the id of a CI trust, and the API
answers with a short-lived access key. The key can only fetch the secrets the
trust lists, it stops working by itself after the lifetime the trust sets
(15 minutes unless the trust says otherwise, at most 1 hour), and an admin can
revoke it earlier in the Console under Settings, API keys, Short-lived access.

  agentruntime login --github-actions --trust 11111111-2222-4333-8444-555555555555
  agentruntime login --github-actions --trust 11111111-2222-4333-8444-555555555555 --export-env

The job needs permissions: id-token: write, in the workflow or in the job.
GitHub then gives it the two variables the CLI reads, ACTIONS_ID_TOKEN_REQUEST_URL
and ACTIONS_ID_TOKEN_REQUEST_TOKEN. The CLI sends the request token only to an
https address on github.com or actions.githubusercontent.com (or a host under
it) and never follows a redirect. The host is checked exactly as it will be dialled:
plain ASCII letters, digits, dots and hyphens only, so an address with a percent
escape in its host, another character, or a trailing dot is refused.

--trust is the id of the CI trust (a workspace admin makes it in the Console under
Settings, Workspace, CI sign-in; it names the repository and the branch or
environment, and the secrets). --audience says who the identity token is for; the
default is https://api.agentruntime.io/workload, and the environment variable
` + envWorkloadAudience + ` sets another (for a different environment).

Without --export-env the key is saved in the current profile with its expiry (the
steps after this one in the same job find it there), and the command refuses when
the profile holds a key that does not expire, unless you pass --replace; use
--profile NAME to keep both. With --export-env the key is not saved in the profile:
it is added as AGENTRUNTIME_PAT to the file named by GITHUB_ENV, for the NEXT steps
of the job (not the current one). The command first prints the line
::add-mask::<key>, so GitHub hides the key in the log; that is the only place the
key is printed. The command refuses when GITHUB_ENV is not set or does not name a
regular file.

It prints API host: <host> on standard error before it asks GitHub for anything, so
the log of the run shows where the identity token goes, and warns when it is not an
agentruntime.io host. The key is saved with the host that issued it; other commands
refuse to send it to another host unless you pass --allow-other-host. On a self-hosted runner
that keeps its home folder, the saved key stays in the config file until it expires:
use --export-env there.

The CLI never prints the identity token, the request token or the key (apart from
the ::add-mask:: line), and nothing is saved or written unless it ends with exit
code 0. Exit codes: 0 signed in, 1 refused or failed, 2 bad flags, 130 Ctrl-C.`

// workloadFlags are the flags that only make sense with --github-actions.
type workloadFlags struct {
	trust     string
	audience  string
	exportEnv bool
}

// workloadOnlyFlags are the names of the flags in workloadFlags, so using one without --github-actions is a usage
// error.
var workloadOnlyFlags = []string{"trust", "audience", "export-env"}

// signInFlags are the flags --device and --github-actions share.
var signInFlags = []string{"api-url", "replace"}

const (
	// envWorkloadAudience overrides the default audience, for another environment or a test.
	envWorkloadAudience = "AGENTRUNTIME_WORKLOAD_AUDIENCE"
	// defaultWorkloadAudience is the audience the hosted service expects an identity token to be made for.
	defaultWorkloadAudience = "https://api.agentruntime.io/workload"
	// envGitHubEnv names the file GitHub reads after a step to set the environment of the next steps.
	envGitHubEnv = "GITHUB_ENV"
)

// addWorkloadFlags registers the flags of --github-actions on the login command.
func addWorkloadFlags(cmd *cobra.Command, f *workloadFlags) {
	fl := cmd.Flags()
	fl.StringVar(&f.trust, "trust", "", "with --github-actions: the id of the CI trust that lets this repository sign in (made in the Console under Settings, Workspace, CI sign-in)")
	fl.StringVar(&f.audience, "audience", "", "with --github-actions: who the identity token is for (default "+defaultWorkloadAudience+"; env "+envWorkloadAudience+")")
	fl.BoolVar(&f.exportEnv, "export-env", false, "with --github-actions: add the key as AGENTRUNTIME_PAT to the file named by GITHUB_ENV (for the job's next steps) instead of saving it in the profile")
}

// loginGitHubActions runs the whole CI sign-in. shared holds the flags it shares with --device (--api-url,
// --replace).
func (a *App) loginGitHubActions(cmd *cobra.Command, f workloadFlags, shared deviceFlags) error {
	// Every input is checked before anything is sent or written. No error repeats what was typed or what the
	// environment holds: a mistyped --trust may be a pasted secret, and the environment holds the request token.
	trust, err := workloadTrust(f.trust)
	if err != nil {
		return &ExitErr{Code: ExitUsage, Err: err}
	}
	audience, err := workloadAudience(cmd, f)
	if err != nil {
		return &ExitErr{Code: ExitUsage, Err: err}
	}
	requester, err := requesterFromEnv()
	if err != nil {
		return &ExitErr{Code: ExitError, Err: err}
	}

	if err := a.loadConfig(); err != nil {
		return err
	}
	name := a.cfg.ProfileName(a.flags.profile)
	var envFile string
	if f.exportEnv {
		envFile = strings.TrimSpace(os.Getenv(envGitHubEnv))
		if err := checkEnvFile(envFile); err != nil {
			return &ExitErr{Code: ExitError, Err: fmt.Errorf("--export-env: %w. Nothing was requested", err)}
		}
	} else {
		if p := a.cfg.Profiles[name]; p != nil && !shared.replace && holdsLongLivedKey(p) {
			return &ExitErr{Code: ExitUsage, Err: fmt.Errorf(
				"profile %q already holds an access key that does not expire. Signing in here would replace it with a short-lived key that can only fetch secrets. "+
					"Use --profile NAME to keep both, or add --replace to replace it (or use --export-env, which leaves the profile alone)", name)}
		}
		// The identity token works once, so a folder that cannot be written is found before it is spent.
		if err := config.CheckWritable(); err != nil {
			return &ExitErr{Code: ExitError, Err: fmt.Errorf("%w; nothing was requested", err)}
		}
	}
	base, err := a.apiBase(shared.apiURL)
	if err != nil {
		return err
	}
	wc, err := bffclient.NewWorkloadClient(base)
	if err != nil {
		return &ExitErr{Code: ExitError, Err: err}
	}
	authority := wc.Authority() // one value: what is shown, stored as the issuer and dialled
	a.announceAPIHost(authority, wc.Host())

	ctx, cancel := a.context(cmd)
	defer cancel()

	idToken, err := requester.IDToken(ctx, audience)
	if err != nil {
		return a.identityTokenFailure(ctx, err)
	}
	grant, err := wc.Exchange(ctx, bffclient.ProviderGitHub, trust, idToken)
	if err != nil {
		return a.exchangeFailure(ctx, err)
	}
	if f.exportEnv {
		return a.exportKey(envFile, shared, grant)
	}
	return a.saveWorkloadKey(name, shared, grant, authority)
}

// ---- inputs -------------------------------------------------------------------------------------------------

// workloadTrust checks --trust and returns the id in its canonical form.
func workloadTrust(given string) (string, error) {
	if strings.TrimSpace(given) == "" {
		return "", errors.New("--trust is required: the id of the CI trust that lets this repository sign in (a workspace admin makes it in the Console under Settings, Workspace, CI sign-in)")
	}
	id, ok := bffclient.NormalizeTrustID(given)
	if !ok {
		return "", errors.New("--trust is not a trust id: it is 36 characters, like 11111111-2222-4333-8444-555555555555 (the Console shows it when the trust is made)")
	}
	return id, nil
}

// workloadAudience is the audience for the identity token: --audience, else the environment, else the default.
func workloadAudience(cmd *cobra.Command, f workloadFlags) (string, error) {
	if cmd.Flags().Changed("audience") {
		aud := strings.TrimSpace(f.audience)
		if err := ghactions.ValidateAudience(aud); err != nil {
			return "", fmt.Errorf("--audience: %w", err)
		}
		return aud, nil
	}
	if aud := strings.TrimSpace(os.Getenv(envWorkloadAudience)); aud != "" {
		if err := ghactions.ValidateAudience(aud); err != nil {
			return "", fmt.Errorf("%s: %w", envWorkloadAudience, err)
		}
		return aud, nil
	}
	return defaultWorkloadAudience, nil
}

// requesterFromEnv reads the two variables GitHub gives a job that may ask for an identity token. A missing one
// means the job lacks permissions: id-token: write (or this is not a GitHub Actions job).
func requesterFromEnv() (*ghactions.Requester, error) {
	reqURL := strings.TrimSpace(os.Getenv(ghactions.EnvRequestURL))
	reqTok := strings.TrimSpace(os.Getenv(ghactions.EnvRequestToken))
	var missing []string
	if reqURL == "" {
		missing = append(missing, ghactions.EnvRequestURL)
	}
	if reqTok == "" {
		missing = append(missing, ghactions.EnvRequestToken)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"the job needs permissions: id-token: write. GitHub gives a job the variables this command reads only when the workflow (or the job) has "+
				"`permissions: id-token: write`, and the command must run inside such a job. Not set: %s", strings.Join(missing, ", "))
	}
	r, err := ghactions.New(reqURL, reqTok)
	if err != nil {
		return nil, fmt.Errorf("%w. Nothing was sent", err)
	}
	return r, nil
}

// ---- failures -------------------------------------------------------------------------------------------------

// workloadStopped is the error for a sign-in that ended because the context did: Ctrl-C, or the --timeout.
func (a *App) workloadStopped(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &ExitErr{Code: ExitError, Err: fmt.Errorf("timed out after %s (raise --timeout). Nothing was saved", a.flags.timeout)}
	}
	return &ExitErr{Code: 130, Err: errors.New("cancelled. Nothing was saved")}
}

// identityTokenFailure turns a failed request to GitHub into the error to show. What GitHub or the network said is
// never shown, only a fixed sentence.
func (a *App) identityTokenFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return a.workloadStopped(ctx)
	}
	return &ExitErr{Code: ExitError, Err: fmt.Errorf("%s. Nothing was saved", safeLine(err.Error()))}
}

// exchangeHints is what the person can check after the server refused the identity token. The server says nothing
// about why, so none of these is claimed to be the reason.
const exchangeHints = `The server does not say why. Check that:
  - the job runs on a branch or in an environment the trust accepts (a trust names the branch or environment it allows)
  - the run is not a pull request (a trust refuses pull requests unless it was made to allow them)
  - the audience is the one the server expects (--audience, or the default for this server)
  - the trust id is the right one, and the trust is turned on
  - the identity token was not used before (each one works once, so run the whole step again)`

// exchangeFailure turns a failed exchange into the error to show: a fixed sentence from the API client, and for a
// refused identity token the list of things to check.
func (a *App) exchangeFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return a.workloadStopped(ctx)
	}
	var ae *bffclient.APIError
	if errors.As(err, &ae) {
		msg := ae.Message
		switch {
		case ae.Code == "invalid_workload_token":
			msg += " " + exchangeHints
		case ae.Status == 429 && ae.RetryAfter != "":
			msg += fmt.Sprintf(" Try again in %s seconds.", ae.RetryAfter)
		}
		return &ExitErr{Code: ExitError, Err: errors.New(msg + "\nNothing was saved.")}
	}
	return &ExitErr{Code: ExitError, Err: fmt.Errorf("the sign-in failed: %s. Nothing was saved", scrubError(err))}
}

// ---- saving -----------------------------------------------------------------------------------------------------

// saveWorkloadKey stores the key and its expiry in the profile and tells the person what they got. The key is never
// printed.
func (a *App) saveWorkloadKey(name string, shared deviceFlags, grant *bffclient.WorkloadGrant, issuedBy string) error {
	// The config is read again here (another step may have changed it since this command started) and only this profile
	// changes on the file as it is now. The guard against replacing a key that does not expire is checked again.
	fresh, err := config.Load()
	if err != nil {
		return a.workloadKeyNotSaved(err.Error(), grant)
	}
	if fresh.Profiles == nil {
		fresh.Profiles = map[string]*config.Profile{}
	}
	prof := fresh.Profiles[name]
	removedLongLived := prof != nil && holdsLongLivedKey(prof)
	if removedLongLived && !shared.replace {
		return a.workloadKeyNotSaved(fmt.Sprintf("profile %q now holds an access key that does not expire; add --replace to replace it, or use --profile NAME", name), grant)
	}
	if prof == nil {
		prof = &config.Profile{}
		fresh.Profiles[name] = prof
	}
	prof.Token = grant.Token
	prof.ExpiresAt = grant.ExpiresAt.UTC().Format(time.RFC3339)
	// The host that issued the key goes with it (the one value the device sign-in stores too), replacing whatever an
	// earlier key left there, so that the other commands send this key only to that host.
	prof.IssuedByHost = issuedBy
	if u := strings.TrimSpace(a.flags.url); u != "" {
		prof.URL = u
	} else if prof.URL == "" {
		prof.URL = config.DefaultURL
	}
	// The current profile is left as it is: a fetch-only key must not become the one whoami and workflows use.
	if err := fresh.Save(); err != nil {
		return a.workloadKeyNotSaved(err.Error(), grant)
	}
	a.cfg = fresh

	scopes, claim := describeScopes(grant.Scopes)
	w := a.Out
	fmt.Fprintf(w, "%s signed in for this job until %s%s; %s\n", a.stdout.Green("✔"), formatLocal(grant.ExpiresAt), inTime(grant.ExpiresAt.Sub(a.nowTime())), claim)
	fmt.Fprintf(w, "  Scopes: %s\n", scopes)
	path, _ := config.Path()
	fmt.Fprintf(w, "  Saved to profile %q in %s, with the host that issued it (%s)\n", name, safeLine(path), safeLine(issuedBy))
	if current := fresh.ProfileName(""); current != name {
		fmt.Fprintf(w, "  Profile %q is not your current profile (%s): use --profile %s, or set AGENTRUNTIME_PROFILE=%s, to use this key.\n",
			safeLine(name), safeLine(current), shellQuote(name), shellQuote(name))
	}
	if removedLongLived {
		fmt.Fprintf(w, "  The access key that was saved in profile %q was removed from it. It is not revoked on the server: revoke it in the Console (Settings, API keys) if you no longer need it.\n", safeLine(name))
	}
	fmt.Fprintln(w, "  The key stays in that file until it expires. On a runner that keeps its home folder between jobs (a self-hosted runner), use --export-env, or a profile in a folder that is removed after the job.")
	fmt.Fprintln(w, "  Other commands that need more rights (whoami, workflows, ...) may be refused with this key.")
	if os.Getenv("AGENTRUNTIME_PAT") != "" {
		fmt.Fprintf(a.Err, "%s AGENTRUNTIME_PAT is set in your environment and overrides the saved key. Unset it to use the key you just saved.\n", a.stderr.Yellow("note:"))
	}
	a.noteAPIURL(shared)
	return nil
}

// workloadKeyNotSaved is the error for a sign-in that worked but whose key could not be put in the profile. The key is
// shown by the server only once and is never printed, so the person is told it is lost, when it ends, and how to
// revoke it.
func (a *App) workloadKeyNotSaved(reason string, grant *bffclient.WorkloadGrant) error {
	return &ExitErr{Code: ExitError, Err: fmt.Errorf(
		"the sign-in worked, but the key could not be saved (%s). It cannot be shown again and it stops working by itself at %s. "+
			"Fix that and run the step again; the unsaved key can be revoked in the Console under Short-lived access",
		safeLine(reason), formatLocal(grant.ExpiresAt))}
}

// announceAPIHost prints on standard error (standard output keeps only the mask line and the result), as the first thing the command does with the network, which API host the job's identity token
// is about to go to, so that the log of the run shows it. A host that is not an agentruntime.io host (or one of the
// loopback hosts) gets a warning too. No confirmation is asked: whoever wrote the workflow already holds both variables
// that are needed and chose the address.
func (a *App) announceAPIHost(authority, host string) {
	fmt.Fprintf(a.Err, "API host: %s\n", safeLine(authority))
	if !a.apiHostIsOfficial(host) {
		fmt.Fprintf(a.Err, "%s the API host is %s, which is not an agentruntime.io host. This job's identity token is sent to it, and the key it makes is saved as coming from it.\n",
			a.stderr.Yellow("warning:"), safeLine(authority))
	}
}

// noteAPIURL says that an API address given on the command line is not remembered.
func (a *App) noteAPIURL(shared deviceFlags) {
	if strings.TrimSpace(shared.apiURL) != "" {
		fmt.Fprintf(a.Err, "%s the API address you gave is not saved. Pass --api-url (or set %s) on later commands that need it.\n", a.stderr.Yellow("note:"), bffclient.EnvAPIURL)
	}
}

// exportKey hands the key to the next steps of the job: it tells GitHub to hide the value, then appends
// AGENTRUNTIME_PAT to the file GitHub reads. The mask line is printed first, so there is no moment at which the key
// is in the job's files and not yet hidden from its log. It is the only line that holds the key.
func (a *App) exportKey(envFile string, shared deviceFlags, grant *bffclient.WorkloadGrant) error {
	fmt.Fprintf(a.Out, "::add-mask::%s\n", grant.Token)
	if err := appendEnvLine(envFile, "AGENTRUNTIME_PAT", grant.Token); err != nil {
		return &ExitErr{Code: ExitError, Err: fmt.Errorf(
			"the sign-in worked, but the key could not be written to the file named by %s (%s). It cannot be shown again and it stops working by itself at %s. "+
				"Run the step again; the unused key can be revoked in the Console under Short-lived access",
			envGitHubEnv, safeLine(err.Error()), formatLocal(grant.ExpiresAt))}
	}
	scopes, claim := describeScopes(grant.Scopes)
	w := a.Out
	fmt.Fprintf(w, "%s AGENTRUNTIME_PAT is set for the next steps of this job until %s%s; %s\n", a.stdout.Green("✔"), formatLocal(grant.ExpiresAt), inTime(grant.ExpiresAt.Sub(a.nowTime())), claim)
	fmt.Fprintf(w, "  Scopes: %s\n", scopes)
	fmt.Fprintf(w, "  Written to the file named by %s; the key is hidden in this job's log. The current step does not see it.\n", envGitHubEnv)
	a.noteAPIURL(shared)
	return nil
}

// ---- the GITHUB_ENV file ------------------------------------------------------------------------------------------

// checkEnvFile finds out, before anything is requested, whether the file GitHub named can be appended to: the
// variable is set, and it names a regular file (a link, a folder or a device is refused) or a file that can be
// created in a folder that exists.
func checkEnvFile(path string) error {
	if path == "" {
		return fmt.Errorf("%s is not set. It names the file GitHub reads to set the environment of the next steps, so this works only inside a GitHub Actions job", envGitHubEnv)
	}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if st, derr := os.Stat(filepath.Dir(path)); derr != nil || !st.IsDir() {
			return fmt.Errorf("the folder of the file named by %s does not exist", envGitHubEnv)
		}
		return nil
	case err != nil:
		return fmt.Errorf("cannot look at the file named by %s (%s)", envGitHubEnv, safeLine(err.Error()))
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s does not name a regular file (a folder, a link or a device is refused)", envGitHubEnv)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("the file named by %s cannot be appended to (%s)", envGitHubEnv, safeLine(err.Error()))
	}
	return f.Close()
}

// envRaceHook is a test seam: it runs, with the stage "before-open" or "after-open", just before and just after the
// GITHUB_ENV file is opened, where a test puts a link or another file in its place.
var envRaceHook func(stage string)

// appendEnvLine appends NAME=value to the file as one line. A file that does not exist is created owner-only (0600
// where the system allows it); an existing file keeps its permissions. A file that does not end in a newline gets
// one first, so the new line is never glued to the last one. The file is opened first and checked as opened, before
// anything is written: what was opened must be a regular file, and the path must still name that very file (not a
// link, not another file put there meanwhile). A file that did not exist is created with O_EXCL, so that a link
// that appears at its path is not followed. value must be one line.
func appendEnvLine(path, name, value string) error {
	if strings.ContainsAny(name+value, "\r\n") || strings.Contains(name, "=") {
		return errors.New("the value is not one line")
	}
	flags := os.O_RDWR | os.O_APPEND
	switch first, err := os.Lstat(path); {
	case err == nil && !first.Mode().IsRegular():
		return errors.New("not a regular file")
	case err != nil && errors.Is(err, os.ErrNotExist):
		flags |= os.O_CREATE | os.O_EXCL
	case err != nil:
		return err
	}
	if envRaceHook != nil {
		envRaceHook("before-open")
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	if envRaceHook != nil {
		envRaceHook("after-open")
	}
	st, err := f.Stat()
	now, lerr := os.Lstat(path)
	if err != nil || lerr != nil || !st.Mode().IsRegular() || !now.Mode().IsRegular() || !os.SameFile(now, st) {
		_ = f.Close()
		return errors.New("not a regular file, or not the file that was checked")
	}
	prefix := ""
	if size := st.Size(); size > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], size-1); err != nil {
			_ = f.Close()
			return err
		}
		if last[0] != '\n' {
			prefix = "\n"
		}
	}
	if _, err := f.WriteString(prefix + name + "=" + value + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
