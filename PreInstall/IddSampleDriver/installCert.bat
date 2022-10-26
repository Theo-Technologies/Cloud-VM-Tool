# Install certificates
CD "C:\IddSampleDriver"
certutil -addstore -f root IddSampleDriver.cer
certutil -addstore -f TrustedPublisher IddSampleDriver.cer

# Install driver
.\nefconw --create-device-node --hardware-id ROOT\iddsampledriver --class-name Display --class-guid 4d36e968-e325-11ce-bfc1-08002be10318
.\nefconw --install-driver --inf-path IddSampleDriver.inf