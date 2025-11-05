// DOM Elements - will be initialized in DOMContentLoaded
let reservationForm;
let confirmationModal;
let closeModal;
let addToCalendarBtn;
let reservationDetails;

// Mobile Navigation - Enhanced for touch devices
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');

if (hamburger && navMenu) {
    // Use touch events for better mobile responsiveness
    hamburger.addEventListener('touchstart', (e) => {
        e.preventDefault();
        navMenu.classList.toggle('active');
        hamburger.classList.toggle('active');
    });

    hamburger.addEventListener('click', (e) => {
        e.preventDefault();
        navMenu.classList.toggle('active');
        hamburger.classList.toggle('active');
    });

    // Close mobile menu when clicking on a link
    document.querySelectorAll('.nav-menu a').forEach(link => {
        link.addEventListener('click', () => {
            navMenu.classList.remove('active');
            hamburger.classList.remove('active');
        });
    });

    // Close mobile menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!hamburger.contains(e.target) && !navMenu.contains(e.target)) {
            navMenu.classList.remove('active');
            hamburger.classList.remove('active');
        }
    });

    // Close mobile menu on window resize if screen becomes large
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            navMenu.classList.remove('active');
            hamburger.classList.remove('active');
        }
    });
}

// Set minimum date to today (no maximum restriction)
const dateInput = document.getElementById('date');
if (dateInput) {
    const today = new Date().toISOString().split('T')[0];
    dateInput.setAttribute('min', today);
    // Removed max date restriction to allow longer advance bookings
}

// Client-side validation functions
const validateName = (name) => {
    if (!name) return false;
    // Very flexible name validation - allow most characters except numbers and special symbols
    return name.length >= 2 && name.length <= 100 && !/^[\d\s\-'\.]+$/.test(name);
};

const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
};

const validatePhone = (phone) => {
    if (!phone) return false;
    // Very flexible phone validation - just needs to have some digits
    const cleanPhone = phone.replace(/\D/g, '');
    return cleanPhone.length >= 7 && cleanPhone.length <= 20;
};

const validateDate = (date) => {
    if (!date) return false;

    // Parse date string (YYYY-MM-DD format) and compare date-only (ignore time/timezone)
    const inputDateParts = date.split('-');
    if (inputDateParts.length !== 3) return false;

    const inputYear = parseInt(inputDateParts[0], 10);
    const inputMonth = parseInt(inputDateParts[1], 10) - 1; // Month is 0-indexed
    const inputDay = parseInt(inputDateParts[2], 10);

    // Get today's date in local timezone (date-only, no time)
    const today = new Date();
    const todayYear = today.getFullYear();
    const todayMonth = today.getMonth();
    const todayDay = today.getDate();

    // Create date objects for comparison (date-only, no time)
    const inputDateOnly = new Date(inputYear, inputMonth, inputDay);
    const todayDateOnly = new Date(todayYear, todayMonth, todayDay);

    // Compare dates (input date should be today or later)
    return inputDateOnly >= todayDateOnly;
};

const validateTime = (time) => {
    const timeRegex = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;
    return timeRegex.test(time);
};

const validateGuests = (guests, venue = 'xix') => {
    const num = parseInt(guests);
    if (venue === 'mirror') {
        return num >= 1 && num <= 300; // Mirror can accommodate up to 300 guests
    }
    return num >= 1 && num <= 20; // XIX restaurant limit
};

const validateSpecialRequests = (requests) => {
    // Special requests are completely optional
    return !requests || requests.length <= 1000;
};

// Real-time validation with visual feedback
const addValidationFeedback = (input, isValid, message) => {
    // Remove existing feedback
    const existingFeedback = input.parentNode.querySelector('.validation-feedback');
    if (existingFeedback) {
        existingFeedback.remove();
    }

    // Remove existing classes
    input.classList.remove('valid', 'invalid');

    if (isValid) {
        input.classList.add('valid');
    } else {
        input.classList.add('invalid');
        if (message) {
            const feedback = document.createElement('div');
            feedback.className = 'validation-feedback';
            feedback.textContent = message;
            feedback.style.color = '#e74c3c';
            feedback.style.fontSize = '0.875rem';
            feedback.style.marginTop = '0.25rem';
            input.parentNode.appendChild(feedback);
        }
    }
};

// Add real-time validation event listeners
const setupRealTimeValidation = () => {
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const phoneInput = document.getElementById('phone');
    const dateInput = document.getElementById('date');
    const timeInput = document.getElementById('time');
    const guestsInput = document.getElementById('guests');
    const specialRequestsInput = document.getElementById('special-requests');

    if (nameInput) {
        nameInput.addEventListener('blur', () => {
            const isValid = validateName(nameInput.value);
            addValidationFeedback(nameInput, isValid,
                isValid ? '' : 'Name must be 2-50 characters and contain only letters, spaces, hyphens, apostrophes, and periods');
        });
    }

    if (emailInput) {
        emailInput.addEventListener('blur', () => {
            const isValid = validateEmail(emailInput.value);
            addValidationFeedback(emailInput, isValid,
                isValid ? '' : 'Please provide a valid email address');
        });
    }

    if (phoneInput) {
        phoneInput.addEventListener('blur', () => {
            const isValid = validatePhone(phoneInput.value);
            addValidationFeedback(phoneInput, isValid,
                isValid ? '' : 'Please provide a valid phone number');
        });
    }

    if (dateInput) {
        dateInput.addEventListener('change', () => {
            const isValid = validateDate(dateInput.value);
            addValidationFeedback(dateInput, isValid,
                isValid ? '' : 'Please select a valid date (today or later)');
        });
    }

    if (timeInput) {
        timeInput.addEventListener('change', () => {
            const isValid = validateTime(timeInput.value);
            addValidationFeedback(timeInput, isValid,
                isValid ? '' : 'Please select a valid time');
        });
    }

    if (guestsInput) {
        guestsInput.addEventListener('change', () => {
            // Detect venue based on current page URL
            const isMirrorPage = window.location.pathname.includes('/mirror');
            const venue = isMirrorPage ? 'mirror' : 'xix';
            const isValid = validateGuests(guestsInput.value, venue);
            const errorMessage = venue === 'mirror'
                ? 'Number of guests must be between 1 and 300'
                : 'Number of guests must be between 1 and 20';
            addValidationFeedback(guestsInput, isValid,
                isValid ? '' : errorMessage);
        });
    }

    if (specialRequestsInput) {
        specialRequestsInput.addEventListener('input', () => {
            const isValid = validateSpecialRequests(specialRequestsInput.value);
            addValidationFeedback(specialRequestsInput, isValid,
                isValid ? '' : 'Special requests must be 500 characters or less');
        });
    }
};

// Initialize real-time validation
setupRealTimeValidation();

// Available time slots based on day of week
const timeSlots = {
    'Monday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Tuesday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Wednesday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Thursday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00'],
    'Friday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00', '22:30'],
    'Saturday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00', '21:30', '22:00', '22:30'],
    'Sunday': ['17:00', '17:30', '18:00', '18:30', '19:00', '19:30', '20:00', '20:30', '21:00']
};

// Update time slots based on selected date
if (dateInput) {
    dateInput.addEventListener('change', function () {
        const selectedDate = this.value;
        const timeSelect = document.getElementById('time');

        if (timeSelect) {
            // Clear existing options
            timeSelect.innerHTML = '<option value="">Loading available times...</option>';

            // Fetch available time slots from API
            fetch(`/api/availability/${selectedDate}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin'
            })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    timeSelect.innerHTML = '<option value="">Select Time</option>';

                    if (data.available && data.available.length > 0) {
                        data.available.forEach(time => {
                            const option = document.createElement('option');
                            option.value = time;
                            option.textContent = formatTime(time);
                            timeSelect.appendChild(option);
                        });
                    } else {
                        const option = document.createElement('option');
                        option.value = '';
                        option.textContent = 'No available times';
                        option.disabled = true;
                        timeSelect.appendChild(option);
                    }
                })
                .catch(error => {
                    console.error('Error fetching availability:', error);
                    timeSelect.innerHTML = '<option value="">Error loading times</option>';

                    // Fallback to static time slots if API fails
                    const dayOfWeek = new Date(selectedDate).toLocaleDateString('en-US', { weekday: 'long' });
                    const fallbackSlots = timeSlots[dayOfWeek] || timeSlots['Monday'];

                    setTimeout(() => {
                        timeSelect.innerHTML = '<option value="">Select Time</option>';
                        fallbackSlots.forEach(time => {
                            const option = document.createElement('option');
                            option.value = time;
                            option.textContent = formatTime(time);
                            timeSelect.appendChild(option);
                        });
                    }, 1000);
                });
        }
    });
}

// Format time for display
function formatTime(time24) {
    const [hours, minutes] = time24.split(':');
    const hour = parseInt(hours);
    const ampm = hour >= 12 ? 'PM' : 'AM';
    const displayHour = hour % 12 || 12;
    return `${displayHour}:${minutes} ${ampm}`;
}

// Check table availability (simplified simulation)
function checkAvailability(date, time, guests) {
    // Simulate some tables being unavailable
    const unavailableSlots = [
        '2024-01-15-19:00',
        '2024-01-15-19:30',
        '2024-01-16-20:00'
    ];

    const slotKey = `${date}-${time}`;
    return !unavailableSlots.includes(slotKey);
}

// Form submission will be handled in DOMContentLoaded event

// Display confirmation modal
function displayConfirmation(reservation) {
    if (!confirmationModal || !reservationDetails) return;

    const date = new Date(reservation.date).toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });

    const time = formatTime(reservation.time);

    reservationDetails.innerHTML = `
        <h3>Reservation Details</h3>
        <p><strong>Name:</strong> ${reservation.name}</p>
        <p><strong>Email:</strong> ${reservation.email}</p>
        <p><strong>Phone:</strong> ${reservation.phone}</p>
        <p><strong>Date:</strong> ${date}</p>
        <p><strong>Time:</strong> ${time}</p>
        <p><strong>Guests:</strong> ${reservation.guests}</p>
        <p><strong>Table:</strong> ${reservation.table || 'Any Available'}</p>
        ${reservation.occasion ? `<p><strong>Occasion:</strong> ${reservation.occasion}</p>` : ''}
        ${reservation.specialRequests ? `<p><strong>Special Requests:</strong> ${reservation.specialRequests}</p>` : ''}
    `;

    confirmationModal.style.display = 'block';

    // Store reservation data for calendar integration
    window.currentReservation = reservation;
}

// Close modal
if (closeModal) {
    closeModal.addEventListener('click', function () {
        confirmationModal.style.display = 'none';
    });
}

// Close modal when clicking outside
if (confirmationModal) {
    window.addEventListener('click', function (e) {
        if (e.target === confirmationModal) {
            confirmationModal.style.display = 'none';
        }
    });
}

// Google Calendar Integration
if (addToCalendarBtn) {
    addToCalendarBtn.addEventListener('click', function () {
        if (!window.currentReservation) return;

        const reservation = window.currentReservation;
        const startDate = new Date(`${reservation.date}T${reservation.time}:00`);
        const endDate = new Date(startDate.getTime() + (2 * 60 * 60 * 1000)); // 2 hours duration

        // Format dates for Google Calendar
        const formatDate = (date) => {
            return date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
        };

        const eventDetails = {
            title: `Restaurant Reservation - ${reservation.name}`,
            description: `Restaurant reservation for ${reservation.guests} guests${reservation.specialRequests ? `\n\nSpecial Requests: ${reservation.specialRequests}` : ''}`,
            location: 'XIX Restaurant, 123 King\'s Road, London SW3 4RD',
            startTime: formatDate(startDate),
            endTime: formatDate(endDate)
        };

        // Create Google Calendar URL
        const googleCalendarUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(eventDetails.title)}&dates=${eventDetails.startTime}/${eventDetails.endTime}&details=${encodeURIComponent(eventDetails.description)}&location=${encodeURIComponent(eventDetails.location)}`;

        // Open Google Calendar in new tab
        window.open(googleCalendarUrl, '_blank');

        // Show success message
        this.textContent = 'Added to Calendar!';
        this.style.background = '#27ae60';

        setTimeout(() => {
            this.textContent = 'Add to Google Calendar';
            this.style.background = '#4285f4';
        }, 3000);
    });
}

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Form validation
function validateForm() {
    const requiredFields = ['name', 'email', 'phone', 'date', 'time', 'guests'];
    let isValid = true;

    requiredFields.forEach(fieldName => {
        const field = document.getElementById(fieldName);
        if (field && !field.value.trim()) {
            field.style.borderColor = '#e74c3c';
            isValid = false;
        } else if (field) {
            field.style.borderColor = '#F0F0F0';
        }
    });

    // Email validation
    const email = document.getElementById('email');
    if (email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (email.value && !emailRegex.test(email.value)) {
            email.style.borderColor = '#e74c3c';
            isValid = false;
        }
    }

    return isValid;
}

// Add real-time validation
document.querySelectorAll('input, select').forEach(field => {
    field.addEventListener('blur', function () {
        if (this.hasAttribute('required') && !this.value.trim()) {
            this.style.borderColor = '#e74c3c';
        } else {
            this.style.borderColor = '#F0F0F0';
        }
    });

    field.addEventListener('input', function () {
        if (this.style.borderColor === 'rgb(231, 76, 60)') {
            this.style.borderColor = '#F0F0F0';
        }
    });
});

// Menu Tab Functionality
const menuTabs = document.querySelectorAll('.menu-tab');
const menuSections = document.querySelectorAll('.menu-section');

menuTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        // Remove active class from all tabs and sections
        menuTabs.forEach(t => t.classList.remove('active'));
        menuSections.forEach(s => s.classList.remove('active'));

        // Add active class to clicked tab
        tab.classList.add('active');

        // Show corresponding section
        const targetSection = document.getElementById(tab.dataset.tab);
        if (targetSection) {
            targetSection.classList.add('active');
        }
    });
});

// Events Filter Functionality
const filterTabs = document.querySelectorAll('.filter-tab');
const eventCards = document.querySelectorAll('.event-card');

filterTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        // Remove active class from all tabs
        filterTabs.forEach(t => t.classList.remove('active'));

        // Add active class to clicked tab
        tab.classList.add('active');

        // Filter event cards
        const filter = tab.dataset.filter;

        eventCards.forEach(card => {
            if (filter === 'all' || card.dataset.category === filter) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    });
});

// Loading state is now handled in the main submit event listener

// Scroll Animation Functionality
function handleScrollAnimations() {
    const animatedElements = document.querySelectorAll('.fade-in, .fade-in-left, .fade-in-right');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Add a small delay for staggered effect
                setTimeout(() => {
                    entry.target.classList.add('visible');
                }, 50);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    animatedElements.forEach((element, index) => {
        // Stagger the animation timing for each element
        element.style.transitionDelay = `${index * 0.05}s`;
        observer.observe(element);
    });
}

// Initialize page-specific functionality
document.addEventListener('DOMContentLoaded', function () {
    console.log('DOMContentLoaded event fired');
    console.log('Script.js loaded and executing');

    // Add a simple test to see if JavaScript is working
    console.log('JavaScript is working! Current URL:', window.location.href);

    // Initialize DOM elements
    reservationForm = document.getElementById('reservationForm');
    confirmationModal = document.getElementById('confirmationModal');
    closeModal = document.querySelector('.close');
    addToCalendarBtn = document.getElementById('addToCalendar');
    reservationDetails = document.getElementById('reservationDetails');

    console.log('DOM elements initialized:');
    console.log('- reservationForm:', reservationForm);
    console.log('- confirmationModal:', confirmationModal);
    console.log('- closeModal:', closeModal);
    console.log('- addToCalendarBtn:', addToCalendarBtn);
    console.log('- reservationDetails:', reservationDetails);

    // Set up modal event listeners
    if (closeModal) {
        closeModal.addEventListener('click', function () {
            if (confirmationModal) {
                confirmationModal.style.display = 'none';
            }
        });
    }

    if (confirmationModal) {
        confirmationModal.addEventListener('click', function (e) {
            if (e.target === confirmationModal) {
                confirmationModal.style.display = 'none';
            }
        });
    }

    if (addToCalendarBtn) {
        addToCalendarBtn.addEventListener('click', addToGoogleCalendar);
    }

    // Test if we can find the form
    const testForm = document.getElementById('reservationForm');
    console.log('Test: Found reservation form:', testForm);
    if (testForm) {
        console.log('Test: Form has', testForm.elements.length, 'elements');
        console.log('Test: Form action:', testForm.action);
        console.log('Test: Form method:', testForm.method);

        // Test if we can attach an event listener
        console.log('Test: Attempting to attach test event listener...');
        testForm.addEventListener('submit', function (e) {
            console.log('Test: Form submission intercepted!');
            e.preventDefault();
            console.log('Test: Default prevented');
        });
        console.log('Test: Event listener attached successfully');
    }

    // Initialize scroll animations
    handleScrollAnimations();

    // Enhanced mobile hover effects for experience cards
    const experienceCards = document.querySelectorAll('.experience-card');

    experienceCards.forEach(card => {
        let isHovered = false;

        // Touch start - start hover effect immediately
        card.addEventListener('touchstart', function (e) {
            isHovered = true;
            card.classList.add('mobile-hover');
            // Don't prevent default to allow any links/buttons to work
        });

        // Touch end - keep hover for a moment then fade
        card.addEventListener('touchend', function (e) {
            // Check if the touch was on a link or button
            const target = e.target;
            const isInteractive = target.closest('a') || target.closest('button') || target.closest('[onclick]');

            if (isInteractive) {
                // If it's an interactive element, let it handle the click naturally
                card.classList.remove('mobile-hover');
                isHovered = false;
            } else {
                // If it's not interactive, keep hover effect
                setTimeout(() => {
                    if (isHovered) {
                        card.classList.remove('mobile-hover');
                        isHovered = false;
                    }
                }, 200); // Keep hover for 200ms after touch
            }
        });

        // Touch cancel - remove hover immediately
        card.addEventListener('touchcancel', function (e) {
            card.classList.remove('mobile-hover');
            isHovered = false;
        });

        // Mouse events for desktop
        card.addEventListener('mouseenter', function () {
            card.classList.add('mobile-hover');
        });

        card.addEventListener('mouseleave', function () {
            card.classList.remove('mobile-hover');
        });
    });

    // Set current page active state
    const pathname = window.location.pathname;
    const currentPage = pathname.split('/').pop() || 'index.html';
    console.log('Current page detected:', currentPage);
    console.log('Full pathname:', pathname);
    const navLinks = document.querySelectorAll('.nav-menu a');

    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('active');
        }
    });

    // Initialize any page-specific features
    if (currentPage === 'menu.html') {
        // Menu page specific initialization
        console.log('Menu page loaded');
    } else if (currentPage === 'events.html') {
        // Events page specific initialization
        console.log('Events page loaded');
    } else if (currentPage === 'reservations.html' || currentPage === 'reservations' || pathname.includes('/reservations')) {
        // Reservations page specific initialization
        console.log('Reservations page loaded - entering reservations section');

        // Handle form submission - now inside DOMContentLoaded
        const reservationForm = document.getElementById('reservationForm');
        console.log('Looking for reservation form...', reservationForm);

        // Form submission is now handled by inline JavaScript in HTML files
        // to prevent duplicate submissions
        if (false) { // Disabled to prevent duplicate submissions
            console.log('Form found, adding event listener...');
            reservationForm.addEventListener('submit', async function (e) {
                console.log('Form submission event triggered!');
                console.log('Form element:', this);
                console.log('Event:', e);
                console.log('Preventing default form submission...');
                e.preventDefault();

                // JavaScript form submission intercepted successfully
                console.log('Default prevented, processing form...');

                // Get form data
                const formData = new FormData(this);
                console.log('FormData entries:');
                for (let [key, value] of formData.entries()) {
                    console.log(key, ':', value);
                }

                // Detect venue based on current page URL
                const isMirrorPage = window.location.pathname.includes('/mirror');
                const venue = isMirrorPage ? 'mirror' : 'xix';

                const reservation = {
                    name: formData.get('name'),
                    email: formData.get('email'),
                    phone: formData.get('phone'),
                    date: formData.get('date'),
                    time: formData.get('time'),
                    guests: formData.get('guests'),
                    table: formData.get('table'),
                    occasion: formData.get('occasion'),
                    specialRequests: formData.get('special-requests'),
                    venue: venue,
                    eventType: formData.get('event-type'),
                    menuPreference: formData.get('menu-preference'),
                    entertainment: formData.get('entertainment')
                };

                console.log('Reservation object:', reservation);
                console.log('Venue detected:', venue);
                console.log('Is Mirror page:', isMirrorPage);
                console.log('Current URL:', window.location.href);
                console.log('Current pathname:', window.location.pathname);

                // Comprehensive client-side validation
                const errors = [];
                console.log('Starting validation...');

                if (!validateName(reservation.name)) {
                    console.log('Name validation failed:', reservation.name);
                    errors.push('Please enter your full name (2-100 characters)');
                } else {
                    console.log('Name validation passed');
                }

                if (!validateEmail(reservation.email)) {
                    console.log('Email validation failed:', reservation.email);
                    errors.push('Please provide a valid email address');
                } else {
                    console.log('Email validation passed');
                }

                if (!validatePhone(reservation.phone)) {
                    console.log('Phone validation failed:', reservation.phone);
                    errors.push('Please provide a valid phone number (7-20 digits)');
                } else {
                    console.log('Phone validation passed');
                }

                if (!validateDate(reservation.date)) {
                    console.log('Date validation failed:', reservation.date);
                    errors.push('Please select a valid date (today or later)');
                } else {
                    console.log('Date validation passed');
                }

                if (!validateTime(reservation.time)) {
                    console.log('Time validation failed:', reservation.time);
                    errors.push('Please select a valid time');
                } else {
                    console.log('Time validation passed');
                }

                if (!validateGuests(reservation.guests, venue)) {
                    console.log('Guests validation failed:', reservation.guests);
                    const errorMessage = venue === 'mirror'
                        ? 'Number of guests must be between 1 and 300'
                        : 'Number of guests must be between 1 and 20';
                    errors.push(errorMessage);
                } else {
                    console.log('Guests validation passed');
                }

                if (!validateSpecialRequests(reservation.specialRequests)) {
                    console.log('Special requests validation failed:', reservation.specialRequests);
                    errors.push('Special requests must be 1000 characters or less');
                } else {
                    console.log('Special requests validation passed');
                }

                console.log('Validation errors:', errors);

                if (errors.length > 0) {
                    // Show validation errors
                    const errorMessage = 'Please correct the following errors:\n\n' + errors.join('\n');
                    console.log('Showing validation errors:', errorMessage);
                    alert(errorMessage);
                    return;
                }

                console.log('All validations passed, proceeding...');

                // Check availability
                if (!checkAvailability(reservation.date, reservation.time, reservation.guests)) {
                    alert('Sorry, this time slot is not available. Please choose another time.');
                    return;
                }

                // Show loading state with mobile-friendly feedback
                const submitBtn = this.querySelector('.submit-button');
                const originalText = submitBtn ? submitBtn.textContent : '';
                if (submitBtn) {
                    submitBtn.textContent = 'Processing...';
                    submitBtn.disabled = true;
                    submitBtn.style.opacity = '0.7';
                    submitBtn.style.transform = 'scale(0.98)';
                }

                // Debug: Log the reservation data being sent
                console.log('Sending reservation data:', reservation);

                // Attempt to send confirmation email via backend first
                try {
                    await sendReservationEmail(reservation);

                    // Display confirmation modal only after successful email sending
                    displayConfirmation(reservation);

                    // Reset form
                    this.reset();
                } catch (error) {
                    console.error('Failed to send reservation email:', error);
                    const errorMessage = error.message.includes('Validation failed')
                        ? `Please check your form: ${error.message}`
                        : 'Sorry, there was an error processing your reservation. Please try again or call us directly.';
                    alert(errorMessage);
                } finally {
                    // Restore button state
                    if (submitBtn) {
                        submitBtn.textContent = originalText;
                        submitBtn.disabled = false;
                    }
                }
            });
        }
    }

    // Fallback: Try to find and attach form handler regardless of page detection
    console.log('Fallback: Looking for reservation form on any page...');
    const fallbackForm = document.getElementById('reservationForm');
    if (fallbackForm) {
        console.log('Fallback: Found reservation form!', fallbackForm);

        // Check if form already has event listener attached
        if (false) { // Disabled to prevent duplicate submissions
            console.log('Fallback: Attaching form submission handler...');
            fallbackForm.addEventListener('submit', async function (e) {
                console.log('Fallback: Form submission event triggered!');
                console.log('Fallback: Preventing default form submission...');
                e.preventDefault();

                // Fallback JavaScript form submission intercepted successfully
                console.log('Fallback: Default prevented, processing form...');

                // Get form data
                const formData = new FormData(this);
                console.log('Fallback: FormData entries:');
                for (let [key, value] of formData.entries()) {
                    console.log(key, ':', value);
                }

                // Detect venue based on current page URL
                const isMirrorPage = window.location.pathname.includes('/mirror');
                const venue = isMirrorPage ? 'mirror' : 'xix';

                const reservation = {
                    name: formData.get('name'),
                    email: formData.get('email'),
                    phone: formData.get('phone'),
                    date: formData.get('date'),
                    time: formData.get('time'),
                    guests: formData.get('guests'),
                    table: formData.get('table'),
                    occasion: formData.get('occasion'),
                    specialRequests: formData.get('special-requests'),
                    venue: venue,
                    eventType: formData.get('event-type'),
                    menuPreference: formData.get('menu-preference'),
                    entertainment: formData.get('entertainment')
                };

                console.log('Fallback: Reservation object:', reservation);
                console.log('Fallback: Venue detected:', venue);
                console.log('Fallback: Is Mirror page:', isMirrorPage);

                // Show loading state
                const submitBtn = this.querySelector('.submit-button');
                const originalText = submitBtn ? submitBtn.textContent : '';
                if (submitBtn) {
                    submitBtn.textContent = 'Processing...';
                    submitBtn.disabled = true;
                }

                try {
                    await sendReservationEmail(reservation);
                    displayConfirmation(reservation);
                    this.reset();
                } catch (error) {
                    console.error('Fallback: Failed to send reservation email:', error);
                    const errorMessage = error.message.includes('Validation failed')
                        ? `Please check your form: ${error.message}`
                        : 'Sorry, there was an error processing your reservation. Please try again or call us directly.';
                    alert(errorMessage);
                } finally {
                    if (submitBtn) {
                        submitBtn.textContent = originalText;
                        submitBtn.disabled = false;
                    }
                }
            });

            // Mark as having listener attached
            fallbackForm.setAttribute('data-listener-attached', 'true');
        } else {
            console.log('Fallback: Form already has event listener attached');
        }
    } else {
        console.log('Fallback: No reservation form found');
    }
});

// Send email helper
async function sendReservationEmail(reservation) {
    console.log('sendReservationEmail called with:', reservation);
    console.log('Making fetch request to /api/send-reservation-email');

    const response = await fetch('/api/send-reservation-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reservation),
        credentials: 'same-origin'
    });

    console.log('Fetch response received:', response);
    console.log('Response status:', response.status);
    console.log('Response ok:', response.ok);

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error('API Error:', errorData);
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log('Email sent successfully:', data);
    return data;
}