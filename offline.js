// Offline Detection and Fallback for XIX Restaurant
class OfflineManager {
    constructor() {
        this.isOnline = navigator.onLine;
        this.offlineBanner = null;
        this.init();
    }

    init() {
        // Register service worker
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
                .then((registration) => {
                    console.log('Service Worker registered successfully:', registration);
                })
                .catch((error) => {
                    console.log('Service Worker registration failed:', error);
                });
        }

        // Listen for online/offline events
        window.addEventListener('online', () => this.handleOnline());
        window.addEventListener('offline', () => this.handleOffline());

        // Check initial status
        if (!this.isOnline) {
            this.handleOffline();
        }

        // Create offline banner
        this.createOfflineBanner();
    }

    createOfflineBanner() {
        this.offlineBanner = document.createElement('div');
        this.offlineBanner.id = 'offline-banner';
        this.offlineBanner.innerHTML = `
            <div class="offline-content">
                <div class="offline-icon">
                    <i class="fas fa-wifi"></i>
                </div>
                <div class="offline-message">
                    <h3>You're currently offline</h3>
                    <p>Don't worry! You can still browse our menu and contact us directly.</p>
                    <div class="offline-contact">
                        <p><strong>Call us directly:</strong></p>
                        <a href="tel:+447796817690" class="phone-link">
                            <i class="fas fa-phone"></i> +44 7796 817690
                        </a>
                        <p class="offline-hours">Open: Mon-Sun 9:00 AM - 11:00 PM</p>
                    </div>
                </div>
                <button class="offline-close" onclick="this.parentElement.parentElement.style.display='none'">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            #offline-banner {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: linear-gradient(135deg, #A8871A 0%, #8B6F1A 100%);
                color: white;
                padding: 15px;
                z-index: 10000;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
                display: none;
                animation: slideDown 0.3s ease-out;
            }
            
            @keyframes slideDown {
                from { transform: translateY(-100%); }
                to { transform: translateY(0); }
            }
            
            .offline-content {
                display: flex;
                align-items: center;
                max-width: 1200px;
                margin: 0 auto;
                gap: 20px;
            }
            
            .offline-icon {
                font-size: 24px;
                opacity: 0.8;
            }
            
            .offline-message h3 {
                margin: 0 0 5px 0;
                font-size: 18px;
                font-weight: 600;
            }
            
            .offline-message p {
                margin: 0 0 10px 0;
                font-size: 14px;
                opacity: 0.9;
            }
            
            .offline-contact {
                display: flex;
                align-items: center;
                gap: 15px;
                flex-wrap: wrap;
            }
            
            .phone-link {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(255,255,255,0.2);
                padding: 8px 16px;
                border-radius: 25px;
                color: white;
                text-decoration: none;
                font-weight: 600;
                transition: background 0.3s ease;
            }
            
            .phone-link:hover {
                background: rgba(255,255,255,0.3);
                color: white;
            }
            
            .offline-hours {
                font-size: 12px;
                opacity: 0.8;
                margin: 0;
            }
            
            .offline-close {
                background: none;
                border: none;
                color: white;
                font-size: 18px;
                cursor: pointer;
                padding: 5px;
                margin-left: auto;
                opacity: 0.8;
                transition: opacity 0.3s ease;
            }
            
            .offline-close:hover {
                opacity: 1;
            }
            
            /* Adjust body padding when banner is shown */
            body.offline-mode {
                padding-top: 80px;
            }
            
            /* Dark mode adjustments */
            .dark-mode #offline-banner {
                background: linear-gradient(135deg, #2a2a2a 0%, #1a1a1a 100%);
            }
            
            .dark-mode .phone-link {
                background: rgba(255,255,255,0.1);
            }
            
            .dark-mode .phone-link:hover {
                background: rgba(255,255,255,0.2);
            }
        `;
        
        document.head.appendChild(style);
        document.body.appendChild(this.offlineBanner);
    }

    handleOffline() {
        this.isOnline = false;
        console.log('App is offline');
        
        if (this.offlineBanner) {
            this.offlineBanner.style.display = 'block';
            document.body.classList.add('offline-mode');
        }
        
        // Show offline message in forms
        this.showOfflineFormMessage();
    }

    handleOnline() {
        this.isOnline = true;
        console.log('App is back online');
        
        if (this.offlineBanner) {
            this.offlineBanner.style.display = 'none';
            document.body.classList.remove('offline-mode');
        }
        
        // Hide offline form message
        this.hideOfflineFormMessage();
    }

    showOfflineFormMessage() {
        // Add offline message to reservation form
        const reservationForm = document.querySelector('#reservation-form');
        if (reservationForm && !document.querySelector('.offline-form-message')) {
            const offlineMessage = document.createElement('div');
            offlineMessage.className = 'offline-form-message';
            offlineMessage.innerHTML = `
                <div class="offline-form-content">
                    <i class="fas fa-wifi"></i>
                    <div>
                        <strong>You're offline</strong>
                        <p>Reservation form is not available offline. Please call us directly:</p>
                        <a href="tel:+447796817690" class="phone-link">
                            <i class="fas fa-phone"></i> +44 7796 817690
                        </a>
                    </div>
                </div>
            `;
            
            // Add styles for offline form message
            const style = document.createElement('style');
            style.textContent = `
                .offline-form-message {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 20px 0;
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }
                
                .offline-form-content {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    width: 100%;
                }
                
                .offline-form-content i {
                    color: #856404;
                    font-size: 20px;
                }
                
                .offline-form-content strong {
                    color: #856404;
                    display: block;
                    margin-bottom: 5px;
                }
                
                .offline-form-content p {
                    margin: 0 0 10px 0;
                    color: #856404;
                    font-size: 14px;
                }
                
                .dark-mode .offline-form-message {
                    background: #2d2d1a;
                    border-color: #4a4a2a;
                }
                
                .dark-mode .offline-form-content i,
                .dark-mode .offline-form-content strong,
                .dark-mode .offline-form-content p {
                    color: #d4d4aa;
                }
            `;
            
            if (!document.querySelector('#offline-form-styles')) {
                style.id = 'offline-form-styles';
                document.head.appendChild(style);
            }
            
            reservationForm.insertBefore(offlineMessage, reservationForm.firstChild);
        }
    }

    hideOfflineFormMessage() {
        const offlineMessage = document.querySelector('.offline-form-message');
        if (offlineMessage) {
            offlineMessage.remove();
        }
    }

    // Method to check if we're online
    isOnlineStatus() {
        return this.isOnline;
    }
}

// Initialize offline manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.offlineManager = new OfflineManager();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OfflineManager;
}
