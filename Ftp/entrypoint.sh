#!/bin/bash
apt-get update && apt-get install net-tools -y

# Generate a random password
PASSWORD=$(openssl rand -base64 12)

# Create the FTP user if it doesn't exist
if ! pure-pw list | grep -q ftpuser; then
    pure-pw useradd ftpuser -f /etc/pure-ftpd/passwd/pureftpd.passwd -m -u ftpuser -d /home/ftpusers/ftpuser -y 1 <<EOF
$PASSWORD
$PASSWORD
EOF
    mkdir -p /home/ftpusers/ftpuser
    chown ftpuser:ftpgroup /home/ftpusers/ftpuser
fi

# Print the FTP user credentials
echo "FTP User: ftpuser"
echo "FTP Password: $PASSWORD"

# Start the FTP server
exec pure-ftpd -l puredb:/etc/pure-ftpd/pureftpd.pdb -E -j -R
