# Simple Explanation

## 🎯 Simple Explanation for Non-Technical People

**Think of it like a hotel key card system:**

1. **Check-in (Login)**: You show ID at the front desk, they give you a key card
2. **Key Card (Session)**: The card lets you access your room and hotel amenities
3. **Security**: The card only works for your room, expires after a while, and has your photo
4. **Check-out (Logout)**: You return the card, and it stops working
5. **Security Guards (Rate Limiting)**: If someone tries too many wrong keys, security gets involved

**For the BAS system:**
- **Login** = Enter username/password to get a session token
- **Session Token** = Like a temporary ID badge that proves you're authorized
- **Protected Endpoints** = Areas that require your ID badge to enter
- **Automatic Expiry** = Your badge stops working after 30 minutes of inactivity
- **Security Monitoring** = System tracks who goes where and when
