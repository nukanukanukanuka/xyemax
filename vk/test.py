import requests, uuid

  # Возьми свежий anonymous_token из последнего успешного Step 0
  token = "anonym.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbm9ueW1faWQiOjIwNzI0NTQwNDYsImFwcF9pZCI6MjI3NDAwMywiaWF0IjoxNzc1MjU0OTg2LCJpc192ZXJpZmllZCI6ZmFsc2UsImV4cCI6MTc3NTM0MTM4Niwic2lnbmVkX3RpbWUiOm51b
  GwsImFub255bV9pZF9sb25nIjo5MDAwMDAwMDAwODc5NTI2OTkxfQ._jrykrmH0MQ9AYI_HtyCofUpbpBOKjB9pz3qoeNfUcc"
  device_id = str(uuid.uuid4())

  headers = {
      "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
      "User-Agent": "VKAndroidApp/8.52-7543 (Android 14; SDK 34; arm64-v8a; Samsung SM-A515F; ru; 2400x1080)",
      "X-VK-Android-Client": "new",
      "Authorization": f"Bearer {token}",
  }
  data = {
      "signature_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # мусор
      "device_id": device_id,
      "lang": "ru",
      "https": "1",
  }

  r = requests.post("https://api.vk.com/oauth/sign_anonymous_token", headers=headers, data=data)
  print(r.status_code, r.text)