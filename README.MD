# Sig Util


```javascript
import {createSigner, createVerifier} from "@certificatum/sig-util"

const PRIVATE_KEY = "PRIVATE_KEY"
const PUBLIC_KEY = "PUBLIC_KEY"
const sign = createSigner(PRIVATE_KEY)
const verify = createVerifier()

const signature = sign("string")

verify(PUBLIC_KEY.toLowerCase(), "string", signature) // true
```