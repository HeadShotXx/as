// Night Crypt - Authentication JavaScript

class NightCryptAuth {
  constructor() {
    this.currentForm = null
    this.init()
  }

  init() {
    // Check if we're on login or register page
    const loginForm = document.getElementById("loginForm")
    const registerForm = document.getElementById("registerForm")

    if (loginForm) {
      this.currentForm = "login"
      this.setupLoginForm()
    } else if (registerForm) {
      this.currentForm = "register"
      this.setupRegisterForm()
    }

    // Check authentication status on page load
    this.checkAuthStatus()
  }

  setupLoginForm() {
    const form = document.getElementById("loginForm")
    const usernameInput = document.getElementById("username")
    const passwordInput = document.getElementById("password")

    form.addEventListener("submit", (e) => this.handleLogin(e))

    // Add input event listeners for real-time validation
    usernameInput.addEventListener("input", () => this.validateField(usernameInput))
    passwordInput.addEventListener("input", () => this.validateField(passwordInput))
  }

  setupRegisterForm() {
    const form = document.getElementById("registerForm")
    const usernameInput = document.getElementById("username")
    const emailInput = document.getElementById("email")
    const passwordInput = document.getElementById("password")
    const confirmPasswordInput = document.getElementById("confirmPassword")

    form.addEventListener("submit", (e) => this.handleRegister(e))

    // Add input event listeners for real-time validation
    usernameInput.addEventListener("input", () => this.validateField(usernameInput))
    emailInput.addEventListener("input", () => this.validateField(emailInput))
    passwordInput.addEventListener("input", () => this.validatePasswordStrength(passwordInput))
    confirmPasswordInput.addEventListener("input", () =>
      this.validatePasswordMatch(passwordInput, confirmPasswordInput),
    )
  }

  async handleLogin(e) {
    e.preventDefault()

    const form = e.target
    const formData = new FormData(form)
    const username = formData.get("username")
    const password = formData.get("password")

    // Validate form
    if (!this.validateForm(form)) {
      return
    }

    try {
      this.setLoading(form, true)

      const response = await fetch("/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        this.showMessage(form, data.message, "success")
        // Redirect to dashboard after successful login
        setTimeout(() => {
          window.location.href = "/dashboard"
        }, 1500)
      } else {
        this.showMessage(form, data.message, "error")
      }
    } catch (error) {
      console.error("Login error:", error)
      this.showMessage(form, "Network error. Please check your connection and try again.", "error")
    } finally {
      this.setLoading(form, false)
    }
  }

  async handleRegister(e) {
    e.preventDefault()

    console.log("Registration form submitted")

    const form = e.target
    const formData = new FormData(form)
    const username = formData.get("username")
    const email = formData.get("email")
    const password = formData.get("password")
    const confirmPassword = formData.get("confirmPassword")
    const terms = formData.get("terms")

    console.log("Form data:", {
      username,
      email,
      hasPassword: !!password,
      hasConfirmPassword: !!confirmPassword,
      terms: !!terms,
    })

    // Validate form
    if (!this.validateForm(form)) {
      console.log("Form validation failed")
      return
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      console.log("Passwords do not match")
      this.showMessage(form, "Passwords do not match.", "error")
      return
    }

    // Check terms acceptance
    if (!terms) {
      console.log("Terms not accepted")
      this.showMessage(form, "Please accept the terms and conditions.", "error")
      return
    }

    try {
      console.log("Sending registration request...")
      this.setLoading(form, true)

      const response = await fetch("/api/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, email, password }),
      })

      console.log("Response received:", response.status, response.statusText)

      let data
      try {
        data = await response.json()
      } catch (parseError) {
        console.error("Failed to parse response as JSON:", parseError)
        throw new Error("Server returned invalid response")
      }

      console.log("Response data:", data)

      if (data.success) {
        this.showMessage(form, data.message, "success")
        // Clear form on success
        form.reset()
        // Redirect to login page after successful registration
        setTimeout(() => {
          window.location.href = "/login"
        }, 2000)
      } else {
        this.showMessage(form, data.message, "error")
      }
    } catch (error) {
      console.error("Registration error:", error)
      this.showMessage(form, "Network error. Please check your connection and try again.", "error")
    } finally {
      this.setLoading(form, false)
    }
  }

  validateForm(form) {
    const inputs = form.querySelectorAll("input[required]")
    let isValid = true

    inputs.forEach((input) => {
      if (!this.validateField(input)) {
        isValid = false
      }
    })

    return isValid
  }

  validateField(input) {
    const value = input.value.trim()
    const fieldName = input.name
    let isValid = true
    let errorMessage = ""

    // Remove existing error styling
    input.classList.remove("error")

    // Check if required field is empty
    if (input.hasAttribute("required") && !value) {
      errorMessage = `${fieldName.charAt(0).toUpperCase() + fieldName.slice(1)} is required`
      isValid = false
    } else {
      // Field-specific validation
      switch (fieldName) {
        case "username":
          if (value.length < 3) {
            errorMessage = "Username must be at least 3 characters long"
            isValid = false
          } else if (!/^[a-zA-Z0-9_]+$/.test(value)) {
            errorMessage = "Username can only contain letters, numbers, and underscores"
            isValid = false
          }
          break

        case "email":
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
          if (!emailRegex.test(value)) {
            errorMessage = "Please enter a valid email address"
            isValid = false
          }
          break

        case "password":
          if (value.length < 8) {
            errorMessage = "Password must be at least 8 characters long"
            isValid = false
          }
          break

        case "confirmPassword":
          const passwordField = input.form.querySelector('input[name="password"]')
          if (passwordField && value !== passwordField.value) {
            errorMessage = "Passwords do not match"
            isValid = false
          }
          break
      }
    }

    if (!isValid) {
      input.classList.add("error")
      this.showFieldError(input, errorMessage)
    } else {
      this.hideFieldError(input)
    }

    return isValid
  }

  validatePasswordStrength(input) {
    const password = input.value
    const strengthIndicator = document.getElementById("passwordStrength")

    if (!strengthIndicator) return

    let strength = 0
    let strengthClass = ""

    if (password.length >= 8) strength++
    if (/[a-z]/.test(password)) strength++
    if (/[A-Z]/.test(password)) strength++
    if (/[0-9]/.test(password)) strength++
    if (/[^A-Za-z0-9]/.test(password)) strength++

    switch (strength) {
      case 0:
      case 1:
        strengthClass = "weak"
        break
      case 2:
        strengthClass = "medium"
        break
      case 3:
        strengthClass = "strong"
        break
      case 4:
      case 5:
        strengthClass = "very-strong"
        break
    }

    strengthIndicator.className = `password-strength ${strengthClass}`
  }

  validatePasswordMatch(passwordInput, confirmInput) {
    const password = passwordInput.value
    const confirmPassword = confirmInput.value

    if (confirmPassword && password !== confirmPassword) {
      confirmInput.classList.add("error")
      this.showFieldError(confirmInput, "Passwords do not match")
      return false
    } else {
      confirmInput.classList.remove("error")
      this.hideFieldError(confirmInput)
      return true
    }
  }

  showFieldError(input, message) {
    // Remove existing error message
    this.hideFieldError(input)

    // Create error message element
    const errorDiv = document.createElement("div")
    errorDiv.className = "field-error"
    errorDiv.textContent = message
    errorDiv.style.cssText = `
            color: var(--error-red, #ff4444);
            font-size: 0.8rem;
            margin-top: 5px;
            margin-left: 5px;
        `

    // Insert after the input
    input.parentNode.appendChild(errorDiv)
  }

  hideFieldError(input) {
    const existingError = input.parentNode.querySelector(".field-error")
    if (existingError) {
      existingError.remove()
    }
  }

  showMessage(form, message, type) {
    // Remove existing messages
    const existingMessage = form.querySelector(".message")
    if (existingMessage) {
      existingMessage.remove()
    }

    // Create message element
    const messageDiv = document.createElement("div")
    messageDiv.className = `message ${type}`
    messageDiv.textContent = message
    messageDiv.style.cssText = `
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 6px;
            font-size: 0.9rem;
            text-align: center;
            ${
              type === "success"
                ? "background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb;"
                : "background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb;"
            }
        `

    // Insert at the top of the form
    form.insertBefore(messageDiv, form.firstChild)

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (messageDiv.parentNode) {
        messageDiv.remove()
      }
    }, 5000)
  }

  setLoading(form, isLoading) {
    const button = form.querySelector(".auth-button")
    const buttonText = button.querySelector("span")
    const buttonLoader = button.querySelector(".button-loader")

    if (isLoading) {
      button.disabled = true
      if (buttonText) buttonText.style.opacity = "0"
      if (buttonLoader) buttonLoader.style.display = "block"
      form.classList.add("loading")
    } else {
      button.disabled = false
      if (buttonText) buttonText.style.opacity = "1"
      if (buttonLoader) buttonLoader.style.display = "none"
      form.classList.remove("loading")
    }
  }

  async checkAuthStatus() {
    try {
      const response = await fetch("/api/user")
      const data = await response.json()

      if (data.success) {
        // User is logged in, redirect to dashboard
        if (window.location.pathname === "/login" || window.location.pathname === "/register") {
          window.location.href = "/dashboard"
        }
      }
    } catch (error) {
      // User is not authenticated, which is fine for login/register pages
      console.log("User not authenticated")
    }
  }

  async logout() {
    try {
      const response = await fetch("/api/logout", {
        method: "POST",
      })

      const data = await response.json()

      if (data.success) {
        window.location.href = "/login"
      }
    } catch (error) {
      console.error("Logout error:", error)
    }
  }
}

// Initialize authentication when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new NightCryptAuth()
})

// Add some utility functions
window.NightCryptAuth = {
  logout: () => {
    const auth = new NightCryptAuth()
    auth.logout()
  },
}
