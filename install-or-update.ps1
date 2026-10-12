scoop bucket add shekel 'https://github.com/shekel588/wreq-cli' 2>$null
scoop update
if (scoop info wreq 2>$null | Select-String 'Installed') { scoop update wreq } else { scoop install wreq }
wreq --version
