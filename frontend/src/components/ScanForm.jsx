/* ============================================================================
   SCANFORM.JSX — the URL input, Tier selection, and Tier 2 credentials form.

   WHY THIS EXISTS: this is the front door of the whole product.
   Tier 1 scans are purely external, passive checks against the public site.
   Tier 2 is the paid, access-gated deep audit tier requiring client-granted access
   via a dedicated, disposable test account (staging URL, username, password).

   ACCESS & RETENTION MODEL:
   - Credentials submitted here are encrypted at rest with authenticated AES-128
     (Fernet) and stored with a 24-hour TTL in MongoDB.
   - The user's account must have an active Starter, Business, or Enterprise plan
     (Tier >= 2) to launch Tier 2 audits; Free users are guided to upgrade.
   - Credentials are used solely by active Tier 2 checks and are zeroized in memory
     immediately upon completion of the scan. Passwords are NEVER written to logs,
     scan finding evidence, or audit reports.
   ========================================================================== */

import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  Search,
  AlertCircle,
  Lock,
  ShieldCheck,
  Eye,
  EyeOff,
  ArrowUpRight,
  Key,
} from 'lucide-react'

import { createScan } from '../lib/api'
import { useAuth } from '../context/AuthContext'

export default function ScanForm() {
  const { user } = useAuth()
  const navigate = useNavigate()

  /* Core scan fields */
  const [url, setUrl] = useState('')
  const [consented, setConsented] = useState(false)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  /* Tier selection: 1 (Standard passive) or 2 (Deep access-gated audit) */
  const [tier, setTier] = useState(1)

  /* Tier 2 test account credentials */
  const [stagingUrl, setStagingUrl] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  const userPlanTier = user?.plan?.tier || 1
  const canRunTier2 = Boolean(user && userPlanTier >= 2)

  function isValidUrl(value) {
    try {
      const parsed = new URL(value)
      return parsed.protocol === 'http:' || parsed.protocol === 'https:'
    } catch {
      return false
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()
    if (submitting) return

    const trimmedUrl = url.trim()

    if (!isValidUrl(trimmedUrl)) {
      setError('Enter a full target URL, including https://')
      return
    }

    if (tier === 2) {
      if (!user) {
        setError('Please sign in to run a Tier 2 deep audit.')
        return
      }
      if (!canRunTier2) {
        setError('Tier 2 audits require a Starter or Business plan. Please upgrade to continue.')
        return
      }
      if (!username.trim()) {
        setError('Enter a test account username or email for Tier 2 auditing.')
        return
      }
      if (!password) {
        setError('Enter a test account password for Tier 2 auditing.')
        return
      }
      if (stagingUrl.trim() && !isValidUrl(stagingUrl.trim())) {
        setError('Enter a valid staging URL (including https://) or leave it blank to use the target URL.')
        return
      }
    }

    setError('')
    setSubmitting(true)

    try {
      const scanOptions = {
        tier,
        credentials:
          tier === 2
            ? {
                stagingUrl: stagingUrl.trim() || undefined,
                username: username.trim(),
                password,
              }
            : null,
      }

      const scan = await createScan(trimmedUrl, consented, scanOptions)

      if (scan.stored === false) {
        setError(
          'The scan ran, but the result could not be saved, so there is no report to open. Check the database connection and try again.',
        )
        return
      }

      navigate(`/dashboard/scan/${scan.id}`)
    } catch (caught) {
      setError(
        caught.message ||
          'The scan could not be started. Check the backend is running on port 8000.',
      )
    } finally {
      setSubmitting(false)
    }
  }

  const isSubmitDisabled =
    !consented ||
    submitting ||
    (tier === 2 && (!canRunTier2 || !username.trim() || !password))

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      {/* --- Tier Selection Tabs ---------------------------------------- */}
      <div className="tier-switch-container" role="radiogroup" aria-label="Select audit tier">
        <button
          type="button"
          role="radio"
          aria-checked={tier === 1}
          className={`tier-switch-btn ${tier === 1 ? 'is-active' : ''}`}
          onClick={() => setTier(1)}
          disabled={submitting}
        >
          <div className="tier-btn-title">Tier 1: Standard Audit</div>
          <div className="tier-btn-sub">Passive external checks · No credentials required</div>
        </button>

        <button
          type="button"
          role="radio"
          aria-checked={tier === 2}
          className={`tier-switch-btn ${tier === 2 ? 'is-active' : ''}`}
          onClick={() => setTier(2)}
          disabled={submitting}
        >
          <div className="tier-btn-title">
            <span>Tier 2: Deep Audit</span>
            <span className="tier-pro-pill">PRO</span>
          </div>
          <div className="tier-btn-sub">Access-gated verification · Client test account required</div>
        </button>
      </div>

      {/* --- Tier 2 Access & Credential Submission Box ------------------- */}
      {tier === 2 && (
        <div className="tier-credentials-card">
          <div className="tier-cred-header">
            <div className="tier-cred-title">
              <Lock size={15} strokeWidth={2} />
              <span>Tier 2 Test Account Access</span>
            </div>
            <span className="tier-secure-pill">
              <ShieldCheck size={13} strokeWidth={2} />
              Encrypted at Rest
            </span>
          </div>

          {!user ? (
            <div className="tier-plan-notice">
              <p>Tier 2 audits require an active Starter or Business subscription.</p>
              <Link to="/login" className="btn-secondary btn-sm">
                Sign in to continue
              </Link>
            </div>
          ) : !canRunTier2 ? (
            <div className="tier-plan-notice">
              <p>
                Your account is currently on the <strong>{user?.plan?.name || 'Free'}</strong> plan.
                Tier 2 access-gated audits require a <strong>Starter</strong> or <strong>Business</strong> subscription.
              </p>
              <Link to="/dashboard/billing" className="btn-primary btn-sm">
                Upgrade plan <ArrowUpRight size={14} />
              </Link>
            </div>
          ) : (
            <div className="tier-cred-fields">
              <p className="tier-cred-note">
                Provide a dedicated, disposable test account created specifically for this audit.
                Never provide your personal or real administrator account.
              </p>

              <div className="tier-input-group">
                <label htmlFor="staging-url-input">
                  Staging / Test Environment URL <span className="label-optional">(optional)</span>
                </label>
                <input
                  id="staging-url-input"
                  type="text"
                  className="input mono"
                  placeholder="https://staging.your-site.com (leave blank to use target URL)"
                  value={stagingUrl}
                  onChange={(e) => setStagingUrl(e.target.value)}
                  disabled={submitting}
                />
              </div>

              <div className="tier-input-row">
                <div className="tier-input-group">
                  <label htmlFor="test-username-input">Test Account Username / Email</label>
                  <input
                    id="test-username-input"
                    type="text"
                    className="input mono"
                    placeholder="e.g. audit_test@example.com"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    disabled={submitting}
                    required
                  />
                </div>

                <div className="tier-input-group">
                  <label htmlFor="test-password-input">Test Account Password</label>
                  <div className="password-input-wrapper">
                    <input
                      id="test-password-input"
                      type={showPassword ? 'text' : 'password'}
                      className="input mono"
                      placeholder="Disposable test account password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={submitting}
                      required
                    />
                    <button
                      type="button"
                      className="password-toggle-btn"
                      onClick={() => setShowPassword((prev) => !prev)}
                      title={showPassword ? 'Hide password' : 'Show password'}
                      tabIndex={-1}
                    >
                      {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </div>
              </div>

              <p className="tier-security-guarantee">
                <Key size={13} strokeWidth={2} />
                <span>
                  Credentials are encrypted with AES-128 and automatically purged after 24 hours.
                  They are scrubbed from memory immediately upon completion of the checks.
                </span>
              </p>
            </div>
          )}
        </div>
      )}

      {/* --- Target URL Input Row --------------------------------------- */}
      <div className="scan-input-row">
        <input
          type="text"
          className="input scan-input mono"
          placeholder="https://your-site.com"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          aria-label="Target URL to scan"
          disabled={submitting}
        />

        <button
          type="submit"
          className="btn-primary"
          disabled={isSubmitDisabled}
        >
          <Search size={16} strokeWidth={2} />
          {submitting
            ? tier === 2
              ? 'Running Tier 2 audit…'
              : 'Scanning…'
            : tier === 2
            ? 'Run Tier 2 audit'
            : 'Run scan'}
        </button>
      </div>

      {/* --- Mandatory Consent Checkbox --------------------------------- */}
      <label className="consent-row">
        <input
          type="checkbox"
          checked={consented}
          onChange={(event) => setConsented(event.target.checked)}
          disabled={submitting}
        />
        <span>
          I confirm I own this site or have written authorisation to scan it.
        </span>
      </label>

      {/* --- Error Display ---------------------------------------------- */}
      {error && (
        <p className="scan-error" role="alert">
          <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
          <span>{error}</span>
        </p>
      )}

      {/* --- Submitting Status Note ------------------------------------- */}
      {submitting && (
        <p className="scan-note">
          {tier === 2
            ? 'Executing Tier 1 baseline checks and Tier 2 access-gated audit probes against the target. This takes a few moments.'
            : 'Running checks against the live site. This takes a few seconds.'}
        </p>
      )}

      {/* --- Explanatory Note ------------------------------------------- */}
      <p className="scan-note">
        {tier === 1
          ? 'Tier 1 audits run purely passive, read-only external checks.'
          : 'Tier 2 audits perform deep, active verification using your supplied test account.'}
      </p>
    </form>
  )
}
