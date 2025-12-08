# Mobile Chatbot Agent

Full-stack chatbot application with React Native (Expo) mobile frontend and FastAPI backend integrated with Microsoft Copilot Studio SDK for AI-powered conversations.

## Project Structure

```
├── backend/              # FastAPI Python backend
│   ├── main.py          # Main server file
│   ├── copilot_service.py    # Copilot Studio integration
│   ├── local_token_cache.py  # Token caching for auth
│   ├── requirements.txt      # Python dependencies
│   └── .env             # Environment variables (not committed)
│
└── mobile/              # React Native Expo mobile app
    ├── app/             # Application screens
    ├── components/      # Reusable components
    └── package.json     # Node dependencies
```

## Prerequisites

- **Python 3.13+** (backend)
- **Node.js 18+** and npm (mobile)
- **Microsoft Copilot Studio** agent credentials
- **Azure AD** account for authentication

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/Shir-hue/Mobile-Chatbot-Agent.git
cd Mobile-Chatbot-Agent
```

### 2. Backend Setup

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Create .env file with your Copilot Studio credentials
# Ask your team lead for the credentials
```

**Create `backend/.env` file:**
```env
COPILOTSTUDIOAGENT__ENVIRONMENTID="your-environment-id"
COPILOTSTUDIOAGENT__SCHEMANAME="your-schema-name"
COPILOTSTUDIOAGENT__TENANTID="your-tenant-id"
COPILOTSTUDIOAGENT__AGENTAPPID="your-agent-app-id"
```

**Start the backend server:**
```bash
python -m uvicorn main:app --reload --host 0.0.0.0
```

The backend will run on `http://0.0.0.0:8000`

**First-time authentication:**
- On first run, a browser window will open for Microsoft login
- Sign in with your Azure AD account (MFA may be required)
- Token will be cached in `.local_token_cache.json` for subsequent runs

### 3. Mobile Setup

# Update backend URL in mobile/app/(tabs)/index.tsx (line 18)
# Change the IP address to your computer's local IP:
const BACKEND_URL = "http://YOUR_IP_ADDRESS:8000/chat";

# Start the Expo development server
npx expo start
```

**Find your IP address:**
- Windows: `ipconfig` (look for IPv4 Address)
- Mac/Linux: `ifconfig` or `ip addr`

**Run on device:**
- Install Expo Go app on your phone
- Scan QR code from terminal
- Or press `a` for Android emulator, `i` for iOS simulator

## Features

- ✅ **AI-Powered Chat**: Integrated with Microsoft Copilot Studio agent
- ✅ **Auto-Greeting**: Automatic intro message on app load
- ✅ **Azure AD Authentication**: Secure login with token caching
- ✅ **Real-time Messaging**: FastAPI backend with async support
- ✅ **Cross-Platform**: React Native works on iOS and Android

## Development

### Backend API Endpoints

- `GET /health` - Health check
- `POST /chat` - Send message to Copilot Studio
- `GET /copilot/status` - Check Copilot connection

### Key Files

**Backend:**
- `copilot_service.py` - Copilot Studio client and message handling
- `local_token_cache.py` - MSAL token cache implementation
- `main.py` - FastAPI routes and server setup

**Mobile:**
- `app/(tabs)/index.tsx` - Main chat interface
- `app/styles/chatStyles.ts` - Chat UI styling

## Troubleshooting

**Backend won't start:**
- Ensure Python 3.13+ is installed: `python --version`
- Check `.env` file exists and has correct credentials
- Run with: `python -m uvicorn main:app --reload`

**Mobile can't connect to backend:**
- Verify backend is running: `http://YOUR_IP:8000/health`
- Update IP address in `index.tsx`
- Ensure phone and computer are on same WiFi network

**Authentication fails:**
- Delete `.local_token_cache.json` and restart backend
- Check Azure AD account has access to Copilot Studio agent
- Verify `TENANTID` and `AGENTAPPID` in `.env`

## Contributing

1. Create a feature branch
2. Make your changes
3. Test both backend and mobile
4. Submit a pull request

## License

Private project - All rights reserved
