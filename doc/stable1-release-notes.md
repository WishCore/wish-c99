# Mist C99 stable preview 16.10

2016-10-

## Known limitations

1. You should not operate with more than 1 identity and 3 contacts
    * identity.list is limited to 4 entries
    * Mist app will start behaving incorrecty with > 3 contacts. , because of the limitation in identity.list. Symptoms include "null" alias name, and missing online messages
2. Wish core's checkConnections function only examines the 3 first identities




