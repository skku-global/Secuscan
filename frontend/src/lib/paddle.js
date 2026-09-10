/* ============================================================================
   PADDLE.JS — Helper for loading and opening Paddle Billing v2 checkout overlay.

   Keeps Paddle SDK lifecycle, initialization, event handling, and theme syncing
   contained so Checkout.jsx remains focused on React view state.
   ========================================================================== */

// Active callback references for checkout events
let activeCheckoutHandlers = null
let paddleInitPromise = null

/**
 * Resolves the appropriate Paddle theme ('dark' or 'light')
 * based on SecuScan's current theme (navy/white/system).
 */
export function getPaddleTheme() {
  const current = document.documentElement.getAttribute('data-theme')
  if (current === 'navy') return 'dark'
  if (current === 'white') return 'light'
  return window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light'
}

/**
 * Ensures the Paddle.js v2 SDK is loaded in the window.
 */
export function loadPaddleScript() {
  if (window.Paddle) {
    return Promise.resolve(window.Paddle)
  }

  if (paddleInitPromise) {
    return paddleInitPromise
  }

  paddleInitPromise = new Promise((resolve, reject) => {
    if (window.Paddle) {
      resolve(window.Paddle)
      return
    }

    const existingScript = document.querySelector('script[src*="paddle.com/paddle/v2/paddle.js"]')
    if (existingScript) {
      existingScript.addEventListener('load', () => resolve(window.Paddle))
      existingScript.addEventListener('error', () => reject(new Error('Failed to load Paddle SDK.')))
      return
    }

    const script = document.createElement('script')
    script.src = 'https://cdn.paddle.com/paddle/v2/paddle.js'
    script.async = true
    script.onload = () => resolve(window.Paddle)
    script.onerror = () => reject(new Error('Failed to load Paddle SDK.'))
    document.head.appendChild(script)
  })

  return paddleInitPromise
}

/**
 * Pre-initializes Paddle with the client-side token and environment.
 */
export async function initPaddle({ clientToken, environment = 'sandbox' } = {}) {
  if (!clientToken) return null

  const Paddle = await loadPaddleScript()
  if (!Paddle) return null

  if (environment && Paddle.Environment?.set) {
    Paddle.Environment.set(environment)
  }

  if (!Paddle.Initialized) {
    Paddle.Initialize({
      token: clientToken,
      eventCallback: (event) => {
        if (!activeCheckoutHandlers) return

        const { name, data } = event || {}
        if (name === 'checkout.completed') {
          activeCheckoutHandlers.isCompleted = true
          activeCheckoutHandlers.onCompleted?.(data)
        } else if (name === 'checkout.closed') {
          activeCheckoutHandlers.onClosed?.({
            completed: activeCheckoutHandlers.isCompleted,
            data,
          })
        } else if (name === 'checkout.error' || name === 'checkout.warning') {
          if (name === 'checkout.error') {
            activeCheckoutHandlers.onError?.(data)
          }
        }
      },
    })
  }

  return Paddle
}

/**
 * Opens the Paddle checkout overlay for a given transaction.
 *
 * @param {Object} options
 * @param {string} [options.clientToken] Paddle client-side token
 * @param {string} options.transactionId Paddle transaction ID (txn_...)
 * @param {string} [options.environment='sandbox'] 'sandbox' or 'production'
 * @param {Function} [options.onCompleted] Called when payment completes
 * @param {Function} [options.onClosed] Called when checkout overlay is closed
 * @param {Function} [options.onError] Called if Paddle reports an error
 */
export async function openPaddleCheckout({
  clientToken,
  transactionId,
  environment = 'sandbox',
  onCompleted,
  onClosed,
  onError,
}) {
  const Paddle = await loadPaddleScript()
  if (!Paddle) {
    throw new Error('Paddle SDK is not available.')
  }

  // Set environment before initialization (sandbox vs live)
  if (environment && Paddle.Environment?.set) {
    Paddle.Environment.set(environment)
  }

  // Track the current active handlers for this checkout invocation
  activeCheckoutHandlers = {
    isCompleted: false,
    onCompleted,
    onClosed,
    onError,
  }

  // Initialize Paddle if not already initialized
  if (!Paddle.Initialized && clientToken) {
    Paddle.Initialize({
      token: clientToken,
      eventCallback: (event) => {
        if (!activeCheckoutHandlers) return

        const { name, data } = event || {}
        if (name === 'checkout.completed') {
          activeCheckoutHandlers.isCompleted = true
          activeCheckoutHandlers.onCompleted?.(data)
        } else if (name === 'checkout.closed') {
          activeCheckoutHandlers.onClosed?.({
            completed: activeCheckoutHandlers.isCompleted,
            data,
          })
        } else if (name === 'checkout.error' || name === 'checkout.warning') {
          if (name === 'checkout.error') {
            activeCheckoutHandlers.onError?.(data)
          }
        }
      },
    })
  } else if (Paddle.Update) {
    try {
      Paddle.Update({
        eventCallback: (event) => {
          if (!activeCheckoutHandlers) return

          const { name, data } = event || {}
          if (name === 'checkout.completed') {
            activeCheckoutHandlers.isCompleted = true
            activeCheckoutHandlers.onCompleted?.(data)
          } else if (name === 'checkout.closed') {
            activeCheckoutHandlers.onClosed?.({
              completed: activeCheckoutHandlers.isCompleted,
              data,
            })
          } else if (name === 'checkout.error') {
            activeCheckoutHandlers.onError?.(data)
          }
        },
      })
    } catch {
      // Fallback to handler set in Initialize
    }
  }

  // Match the active SecuScan theme (dark/navy vs light/white)
  const theme = getPaddleTheme()

  Paddle.Checkout.open({
    transactionId,
    settings: {
      displayMode: 'overlay',
      theme,
      locale: 'en',
    },
  })
}
