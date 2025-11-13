// Night Crypt - Index Page JavaScript
let currentSlide = 0
const slides = document.querySelectorAll(".carousel-image")
const dots = document.querySelectorAll(".dot")
let autoSlideInterval

// Showcase content data
const showcaseData = [
  {
    title: "Advanced Trading Dashboard",
    text: "Experience real-time cryptocurrency trading with our advanced dashboard. Monitor your portfolio, analyze market trends, and execute trades with precision.",
    features: ["Real-time market data", "Advanced charting tools", "Portfolio tracking", "Risk management"],
  },
  {
    title: "Portfolio Analytics",
    text: "Get comprehensive insights into your cryptocurrency investments with detailed analytics and performance metrics.",
    features: ["Performance tracking", "Risk assessment", "Profit/loss analysis", "Asset allocation"],
  },
  {
    title: "Secure Wallet Integration",
    text: "Connect your wallets securely and manage all your cryptocurrency assets from one centralized platform.",
    features: ["Multi-wallet support", "Hardware wallet integration", "Security protocols", "Transaction history"],
  },
  {
    title: "Market Analysis Tools",
    text: "Make informed decisions with our comprehensive market analysis tools and real-time data feeds.",
    features: ["Technical indicators", "Market sentiment", "Price predictions", "News integration"],
  },
]

// Initialize carousel
function initCarousel() {
  showSlide(0)
  startAutoSlide()
}

// Show specific slide
function showSlide(n) {
  // Hide all slides
  slides.forEach((slide) => slide.classList.remove("active"))
  dots.forEach((dot) => dot.classList.remove("active"))

  // Show current slide
  if (slides[n]) {
    slides[n].classList.add("active")
    dots[n].classList.add("active")
    updateShowcaseContent(n)
  }

  currentSlide = n
}

// Change slide (manual navigation)
function changeSlide(direction) {
  stopAutoSlide()
  currentSlide += direction

  if (currentSlide >= slides.length) {
    currentSlide = 0
  } else if (currentSlide < 0) {
    currentSlide = slides.length - 1
  }

  showSlide(currentSlide)
  startAutoSlide()
}

// Go to specific slide (dot navigation)
function currentSlideFunc(n) {
  stopAutoSlide()
  showSlide(n - 1)
  startAutoSlide()
}

// Update showcase content
function updateShowcaseContent(slideIndex) {
  const data = showcaseData[slideIndex]
  const titleElement = document.getElementById("showcaseTitle")
  const textElement = document.getElementById("showcaseText")
  const featuresElement = document.getElementById("showcaseFeatures")

  if (titleElement && textElement && featuresElement) {
    titleElement.textContent = data.title
    textElement.textContent = data.text

    // Update features list
    featuresElement.innerHTML = ""
    data.features.forEach((feature) => {
      const li = document.createElement("li")
      li.textContent = feature
      featuresElement.appendChild(li)
    })
  }
}

// Auto slide functionality
function startAutoSlide() {
  autoSlideInterval = setInterval(() => {
    currentSlide = (currentSlide + 1) % slides.length
    showSlide(currentSlide)
  }, 5000) // Change slide every 5 seconds
}

function stopAutoSlide() {
  if (autoSlideInterval) {
    clearInterval(autoSlideInterval)
  }
}

// Smooth scroll to section
function scrollToSection(sectionId) {
  const section = document.getElementById(sectionId)
  if (section) {
    section.scrollIntoView({
      behavior: "smooth",
      block: "start",
    })
  }
}

// Navigation active state
function updateActiveNav() {
  const sections = ["home", "showcase", "prices"]
  const navLinks = document.querySelectorAll(".nav-link")

  window.addEventListener("scroll", () => {
    let current = ""

    sections.forEach((sectionId) => {
      const section = document.getElementById(sectionId)
      if (section) {
        const sectionTop = section.offsetTop - 100
        const sectionHeight = section.offsetHeight

        if (window.scrollY >= sectionTop && window.scrollY < sectionTop + sectionHeight) {
          current = sectionId
        }
      }
    })

    navLinks.forEach((link) => {
      link.classList.remove("active")
      if (link.getAttribute("href") === `#${current}`) {
        link.classList.add("active")
      }
    })
  })
}

// Check user authentication status
function checkAuthStatus() {
  // This would typically check with your server
  // For now, we'll simulate checking session storage or cookies
  const navRight = document.getElementById("navRight")

  // Simulate checking if user is logged in
  const isLoggedIn = sessionStorage.getItem("userId") || localStorage.getItem("userId")

  if (isLoggedIn && navRight) {
    // Show username instead of auth links
    navRight.innerHTML = `
            <span class="username-display">Welcome, User</span>
            <a href="dashboard" class="nav-auth">Dashboard</a>
        `
  }
}

// Initialize everything when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  initCarousel()
  updateActiveNav()
  checkAuthStatus()

  // Add click event listeners for navigation
  document.querySelectorAll('.nav-link[href^="#"]').forEach((link) => {
    link.addEventListener("click", function (e) {
      e.preventDefault()
      const targetId = this.getAttribute("href").substring(1)
      scrollToSection(targetId)
    })
  })
})

// Pause auto-slide when user hovers over carousel
document.querySelector(".image-carousel")?.addEventListener("mouseenter", stopAutoSlide)
document.querySelector(".image-carousel")?.addEventListener("mouseleave", startAutoSlide)

// Make functions globally available for onclick handlers
window.changeSlide = changeSlide
window.currentSlide = currentSlideFunc
window.scrollToSection = scrollToSection
