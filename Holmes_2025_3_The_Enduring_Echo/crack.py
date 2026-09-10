from Crypto.Hash import MD4

target_hash = "532303a6fa70b02c905f950b60d7da51"
known = "Watson_20250824"

for hour in range (24):
    for minute in range (60):
        for second in range (60):
            timestamp = f"{hour:02d}{minute:02d}{second:02d}"
            password = f"{known}{timestamp}"

            hash = MD4.new(password.encode('utf-16le')).hexdigest()
            if hash == target_hash:
                print(password)
                exit()
            