// Payment integration with Stripe
class PaymentHandler {
    constructor() {
        this.stripe = null;
        this.elements = null;
        this.cardElement = null;
        this.initializeStripe();
    }

    async initializeStripe() {
        try {
            // Get publishable key from server
            const response = await fetch('/api/stripe-config');
            const { publishableKey } = await response.json();

            this.stripe = Stripe(publishableKey);
            this.elements = this.stripe.elements();
            this.setupCardElement();
        } catch (error) {
            console.error('Failed to initialize Stripe:', error);
            this.showError('Failed to initialize payment system');
        }
    }

    setupCardElement() {
        this.cardElement = this.elements.create('card', {
            style: {
                base: {
                    fontSize: '16px',
                    color: '#424770',
                    '::placeholder': {
                        color: '#aab7c4',
                    },
                },
            },
        });

        this.cardElement.mount('#card-element');

        // Handle real-time validation errors
        this.cardElement.on('change', (event) => {
            const displayError = document.getElementById('card-errors');
            if (event.error) {
                displayError.textContent = event.error.message;
            } else {
                displayError.textContent = '';
            }
        });
    }

    async processPayment(amount, reservationId, eventId, customerEmail, customerName) {
        try {
            // Create payment intent
            const response = await fetch('/api/create-payment', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    amount: amount,
                    eventId: eventId,
                    reservationId: reservationId,
                    customerEmail: customerEmail,
                    customerName: customerName
                })
            });

            if (!response.ok) {
                throw new Error('Failed to create payment intent');
            }

            const { clientSecret } = await response.json();

            // Confirm payment
            const { error } = await this.stripe.confirmCardPayment(clientSecret, {
                payment_method: {
                    card: this.cardElement,
                    billing_details: {
                        name: customerName,
                        email: customerEmail,
                    },
                }
            });

            if (error) {
                throw new Error(error.message);
            }

            return { success: true };
        } catch (error) {
            console.error('Payment error:', error);
            throw error;
        }
    }

    showError(message) {
        const errorMessage = document.getElementById('errorMessage');
        const errorText = document.getElementById('errorText');
        errorText.textContent = message;
        errorMessage.style.display = 'block';

        // Hide success message if shown
        document.getElementById('successMessage').style.display = 'none';
    }

    showSuccess() {
        const successMessage = document.getElementById('successMessage');
        successMessage.style.display = 'block';

        // Hide error message if shown
        document.getElementById('errorMessage').style.display = 'none';

        // Hide payment form
        document.getElementById('payment-form').style.display = 'none';
        document.getElementById('paymentSummary').style.display = 'none';
    }
}

// Initialize payment handler when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    const paymentHandler = new PaymentHandler();

    // Get URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const amount = parseFloat(urlParams.get('amount')) || 0;
    const reservationId = urlParams.get('reservationId');
    const eventId = urlParams.get('eventId');

    // Update payment summary
    document.getElementById('reservationFee').textContent = `£${amount.toFixed(2)}`;
    document.getElementById('serviceCharge').textContent = '£0.00';
    document.getElementById('totalAmount').textContent = `£${amount.toFixed(2)}`;

    // Handle form submission
    const form = document.getElementById('payment-form');
    form.addEventListener('submit', async function (event) {
        event.preventDefault();

        const submitButton = document.getElementById('submit-payment');
        const buttonText = document.getElementById('button-text');
        const loading = document.getElementById('loading');

        // Show loading state
        submitButton.disabled = true;
        buttonText.textContent = 'Processing...';
        loading.style.display = 'block';

        try {
            const customerName = document.getElementById('customer-name').value;
            const customerEmail = document.getElementById('customer-email').value;

            await paymentHandler.processPayment(
                amount,
                reservationId,
                eventId,
                customerEmail,
                customerName
            );

            paymentHandler.showSuccess();
        } catch (error) {
            paymentHandler.showError(error.message);
        } finally {
            submitButton.disabled = false;
            buttonText.textContent = 'Pay Now';
            loading.style.display = 'none';
        }
    });
});
