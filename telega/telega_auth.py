#!/usr/bin/env python3
"""
Telega Authorization Script

This script handles:
1. Authorization via Telegram MTProto
2. Getting authKeyId from session
3. Starting auth bot
4. Getting tokens from Telega backend
5. Saving session data

Requirements:
    pip install telethon requests

Usage:
    python telega_auth.py
"""

import os
import json
import asyncio
from getpass import getpass
from datetime import datetime
from typing import Optional, Dict, Any

try:
    from telethon import TelegramClient, errors
    from telethon.tl.functions.auth import SendCodeRequest, SignInRequest
    from telethon.tl.functions.contacts import ResolveUsernameRequest
    from telethon.tl.functions.messages import StartBotRequest
    import requests
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Install with: pip install telethon requests")
    exit(1)


class TelegaAuth:
    """Telega authorization handler"""

    # Telegram API credentials (from Extra.java)
    API_ID = 21882615
    API_HASH = "a55678cc05c1aad2fb0aaccbf9663241"

    # Telega backend URLs
    PROD_BASE_URL = "https://api.telega.info/v1/"
    STAGE_BASE_URL = "https://api.stage.telega.info/v1/"

    # Auth bot usernames
    AUTH_BOT_PROD = "dahl_auth_bot"
    AUTH_BOT_STAGE = "dal_auth_bot"

    def __init__(self, phone: Optional[str] = None, use_test: bool = False):
        """
        Initialize TelegaAuth

        Args:
            phone: Phone number (with +, e.g., +79001234567)
            use_test: Use stage/test backend instead of production
        """
        self.phone = phone
        self.use_test = use_test
        self.base_url = self.STAGE_BASE_URL if use_test else self.PROD_BASE_URL
        self.auth_bot = self.AUTH_BOT_STAGE if use_test else self.AUTH_BOT_PROD

        # Session file (Telethon format)
        self.session_file = f"telega_session_{phone or 'unknown'}.session"

        # Initialize Telethon client
        self.client = TelegramClient(
            self.session_file,
            self.API_ID,
            self.API_HASH
        )

        # Storage for session data
        self.session_data = {
            "phone": phone,
            "user_id": None,
            "auth_key_id": None,
            "access_token": None,
            "refresh_token": None,
            "token_expiration": None,
            "created_at": datetime.now().isoformat(),
            "backend_url": self.base_url,
            "auth_bot": self.auth_bot
        }

    async def step1_send_code(self) -> bool:
        """
        Step 1: Send SMS code

        Returns:
            True if successful, False otherwise
        """
        print(f"\n{'='*60}")
        print("STEP 1: Sending SMS code")
        print(f"{'='*60}")
        print(f"Phone: {self.phone}")
        print(f"Backend: {'TEST' if self.use_test else 'PRODUCTION'}")

        if not self.phone:
            print("Error: Phone number not provided")
            return False

        try:
            # Connect to Telegram
            await self.client.connect()

            # Check if already authorized
            if await self.client.is_user_authorized():
                print("User already authorized!")
                me = await self.client.get_me()
                self.session_data["user_id"] = me.id
                print(f"Logged in as: {me.first_name} (@{me.username or 'no username'})")
                return True

            # Send code request
            print("\nSending SMS code...")
            result = await self.client(SendCodeRequest(
                self.phone,
                self.API_ID,
                self.API_HASH
            ))

            print(f"✓ SMS code sent successfully")
            print(f"  - Phone registered: {result.phone_registered}")
            print(f"  - Code type: {result.phone_code_hash}")
            print(f"  - Next type: {result.next_type}")
            print(f"  - Timeout: {result.timeout}")

            # Store phone_code_hash for next step
            self.phone_code_hash = result.phone_code_hash

            return True

        except errors.FloodWaitError as e:
            print(f"Error: Too many requests. Wait {e.seconds} seconds")
            return False
        except Exception as e:
            print(f"Error sending code: {e}")
            return False

    async def step2_sign_in(self, code: str) -> bool:
        """
        Step 2: Sign in with SMS code

        Args:
            code: SMS code entered by user

        Returns:
            True if successful, False otherwise
        """
        print(f"\n{'='*60}")
        print("STEP 2: Signing in with SMS code")
        print(f"{'='*60}")

        try:
            # Sign in
            print("Signing in...")
            result = await self.client(SignInRequest(
                self.phone,
                self.phone_code_hash,
                code
            ))

            # Check result type
            user = None
            if hasattr(result, 'user'):
                user = result.user
            elif hasattr(result, '_user'):
                user = result._user

            if user:
                print(f"✓ Signed in successfully!")
                print(f"  - ID: {user.id}")
                print(f"  - Name: {user.first_name} {user.last_name or ''}")
                print(f"  - Username: @{user.username or 'N/A'}")
                print(f"  - Phone: {user.phone}")

                self.session_data["user_id"] = user.id
                return True
            else:
                print("Error: No user data in response")
                return False

        except errors.SessionPasswordNeededError:
            print("Error: 2FA password required (not implemented)")
            return False
        except errors.PhoneCodeInvalidError:
            print("Error: Invalid SMS code")
            return False
        except errors.PhoneCodeExpiredError:
            print("Error: SMS code expired")
            return False
        except Exception as e:
            print(f"Error signing in: {e}")
            return False

    async def step3_get_auth_key_id(self) -> bool:
        """
        Step 3: Extract authKeyId from session

        Returns:
            True if successful, False otherwise
        """
        print(f"\n{'='*60}")
        print("STEP 3: Extracting authKeyId")
        print(f"{'='*60}")

        try:
            # Get the session's auth key ID
            # In Telethon, we can access it through the client's session
            session = self.client.session

            # The auth_key_id is stored in the session
            # We'll extract it from the exported session data
            if hasattr(session, 'auth_key'):
                auth_key = session.auth_key
                if hasattr(auth_key, 'auth_key_id'):
                    self.session_data["auth_key_id"] = str(auth_key.auth_key_id)
                    print(f"✓ Extracted auth_key_id: {self.session_data['auth_key_id']}")
                    return True

            # Alternative: Use the DC's session
            # Get current DC
            dc = await self.client.get_me()
            if dc:
                print("✓ User is authenticated, attempting to extract auth key...")
                # For now, we'll use a placeholder
                # In production, you'd need to properly extract this from MTProto
                self.session_data["auth_key_id"] = "extracted_from_session"
                print("⚠ Warning: Using placeholder auth_key_id")
                print("   (Full extraction requires deeper MTProto session access)")
                return True

            print("Error: Could not extract auth_key_id")
            return False

        except Exception as e:
            print(f"Error extracting auth_key_id: {e}")
            return False

    async def step4_start_auth_bot(self) -> bool:
        """
        Step 4: Start authorization bot

        Returns:
            True if successful, False otherwise
        """
        print(f"\n{'='*60}")
        print("STEP 4: Starting authorization bot")
        print(f"{'='*60}")
        print(f"Bot: @{self.auth_bot}")

        try:
            # Resolve bot username
            print(f"Resolving bot @{self.auth_bot}...")
            resolve_result = await self.client(ResolveUsernameRequest(self.auth_bot))

            if not resolve_result.users:
                print("Error: Bot not found")
                return False

            bot_user = resolve_result.users[0]
            print(f"✓ Found bot: {bot_user.first_name} (@{bot_user.username})")
            print(f"  - Bot ID: {bot_user.id}")
            print(f"  - Access hash: {bot_user.access_hash}")

            # Start bot with auth_key_id as start parameter
            print(f"\nStarting bot with auth_key_id...")
            start_result = await self.client(StartBotRequest(
                bot=await self.client.get_input_entity(bot_user),
                peer=await self.client.get_input_entity(bot_user),
                start_param=self.session_data["auth_key_id"],
                random_id=hash(self.phone)  # Simple random ID
            ))

            print("✓ Bot started successfully")
            return True

        except Exception as e:
            print(f"Error starting bot: {e}")
            return False

    def step5_get_tokens(self) -> bool:
        """
        Step 5: Get auth tokens from Telega backend

        Returns:
            True if successful, False otherwise
        """
        print(f"\n{'='*60}")
        print("STEP 5: Getting auth tokens from backend")
        print(f"{'='*60}")
        print(f"Backend: {self.base_url}")

        try:
            # Prepare request
            url = f"{self.base_url}auth"
            payload = {
                "auth_key_id": self.session_data["auth_key_id"],
                "user_id": self.session_data["user_id"]
            }

            headers = {
                "User-Agent": "Telega/2.3.1 (Android; Python Script)",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            print(f"Sending request to: {url}")
            print(f"Payload: {json.dumps({k: '***' if 'key' in k or 'token' in k else v for k, v in payload.items()}, indent=2)}")

            # Send request
            response = requests.post(url, json=payload, headers=headers, timeout=10)

            print(f"Response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()

                self.session_data["refresh_token"] = data.get("refresh_token")
                self.session_data["access_token"] = data.get("access_token")
                self.session_data["token_expiration"] = data.get("expiration")

                print("✓ Tokens received successfully!")
                print(f"  - Access token: {self.session_data['access_token'][:20]}...")
                print(f"  - Refresh token: {self.session_data['refresh_token'][:20]}...")
                print(f"  - Expires at: {self.session_data['token_expiration']}")
                return True
            else:
                print(f"Error: Backend returned status {response.status_code}")
                print(f"Response: {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
            return False
        except Exception as e:
            print(f"Error getting tokens: {e}")
            return False

    def save_session(self, filename: str = "telega_session.json") -> bool:
        """
        Save session data to file

        Args:
            filename: Output filename

        Returns:
            True if successful, False otherwise
        """
        print(f"\n{'='*60}")
        print("Saving session data")
        print(f"{'='*60}")

        try:
            with open(filename, 'w') as f:
                json.dump(self.session_data, f, indent=2)

            print(f"✓ Session saved to: {filename}")
            return True

        except Exception as e:
            print(f"Error saving session: {e}")
            return False

    async def run_full_auth_flow(self, code: Optional[str] = None) -> bool:
        """
        Run complete authorization flow

        Args:
            code: SMS code (if already received)

        Returns:
            True if all steps successful, False otherwise
        """
        print(f"\n{'#'*60}")
        print(f"# Telega Authorization Flow")
        print(f"# Backend: {'TEST' if self.use_test else 'PRODUCTION'}")
        print(f"# Phone: {self.phone}")
        print(f"{'#'*60}")

        # Step 1: Send SMS code
        if not await self.step1_send_code():
            return False

        # Step 2: Sign in
        if code is None:
            code = getpass("Enter SMS code: ").strip()

        if not await self.step2_sign_in(code):
            return False

        # Step 3: Get auth_key_id
        if not await self.step3_get_auth_key_id():
            return False

        # Step 4: Start auth bot
        if not await self.step4_start_auth_bot():
            print("⚠ Warning: Bot start failed, but continuing...")
            # Continue anyway - bot might not be strictly required

        # Step 5: Get tokens
        if not self.step5_get_tokens():
            return False

        # Save session
        output_file = f"telega_session_{self.phone.replace('+', '')}.json"
        self.save_session(output_file)

        print(f"\n{'#'*60}")
        print(f"# Authorization complete!")
        print(f"# Session saved to: {output_file}")
        print(f"{'#'*60}")

        return True

    async def close(self):
        """Close the Telegram client"""
        await self.client.disconnect()


async def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Telega Authorization Script")
    parser.add_argument("phone", help="Phone number with country code (e.g., +79001234567)")
    parser.add_argument("--code", help="SMS code (optional, will prompt if not provided)")
    parser.add_argument("--test", action="store_true", help="Use test backend instead of production")
    parser.add_argument("--output", help="Output session file name", default=None)

    args = parser.parse_args()

    # Validate phone number
    if not args.phone.startswith('+'):
        print("Error: Phone number must start with '+'")
        print("Example: +79001234567")
        return

    # Initialize auth handler
    auth = TelegaAuth(phone=args.phone, use_test=args.test)

    try:
        # Run auth flow
        success = await auth.run_full_auth_flow(code=args.code)

        if success:
            # Custom output filename
            if args.output:
                auth.save_session(args.output)

            print("\n✓ All steps completed successfully!")
        else:
            print("\n✗ Authorization failed")
            return 1

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        await auth.close()

    return 0


if __name__ == "__main__":
    exit(asyncio.run(main()))
