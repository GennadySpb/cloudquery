package registry

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/openpgp"
)

const cloudQueryPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
NdQkdLbveQ+US4vVAzRFJjRAvGVq14lRxiTreQ==
=9Zuc
-----END PGP PUBLIC KEY BLOCK-----`

const gennadySpbPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGCulhoBEAC7ZCffTBxGS6vkEkIsqHywo4ozrbROdKEwGRuFDaeNpeeIRF12
OiDmU5XK5pqCfHdSeOasLJHuoRUvhjq7J45QqcDBFcliHxFT0a+nHWO2JWjKoosy
cAZ5EybMPBOuFxh3JSx1Z+gDTykNdRxePtyoJfZGVGKTj7LwusgVfuYorp/2TWy4
JuRWx67Ws5Ib1q4Wbut/siz/7sjlDMSe7XbSueJBepHR911ztxCT1w+lrk6DkYWS
JV3Z9JQUr+jTQ079u3D4/fYkI+s4Qr3uvg7JlMfWchAgFa9jjptl2M2JhbNbo9uT
sNbk1MN2LWFAqdM/8kqCrc8OdPBQroAWgPpoW6JTckB6DgRpftmdDq0n/Zt//jyk
XOp7xsLTprfzxN7BFtCiXD/hBUZu57bcDS+7BLsWdMIUB/6h1d7MGk+vpwyFvAPL
5TjzJP3o+tabBdBH8djOVmiwKXu46/3sS6P3ezB14ecaML3duBZA0a9FjjBv5+ke
vjRQmYZzARRmLEuwpRjojZHfcY7fRmpPxPM0uspYan0egr68G7+OGlasjr2MsYkR
DOmSY+UVgA+0/Nds24+TBJpxMXF3nXLeJFrv7g9rALPiZtnaeJKM3RpQLGtXyXJU
u3FouooaWL6oymf2g+XN4Htf4QDwoR0+b7v9S24OSq8gwpkyuRVL8SeEeQARAQAB
tDBjbG91ZHF1ZXJ5LXByb3ZpZGVyLXlhbmRleCA8bm9lbWFpbEBub2VtYWlsLmNv
bT6JAlIEEwEIADwWIQSZ8Uv+O/yvYPdXRIZ0HR3z/M+PRQUCYK6WGgIbAwULCQgH
AgMiAgEGFQoJCAsCBBYCAwECHgcCF4AACgkQdB0d8/zPj0U4ow/6AiXDEZ7buRvj
DOE6K51vUnZ4Krg1ClLAHySLgZRJYoNnhX8A8egGL0GdJWJQMySGnwRNxsMTEo+v
TEQ0h1WLP7uaO8e+Js0qakLOxyz1yrvvCegDVQLFpFsL77USdzqH46t5bLUefSn9
9A8wKYVBAA+LogWnsrWyBRAoKwrlReWbUT0qeZVUGfpH9Ja1cG+yhuX1vxQKRX9f
1Of3p0ogNeh2qL8u/RQjGpqE/mO+mOkAVpMVfaCGU6ThY0ey+jHGq5izA6LKvLK6
5DVSwXqcQ8FWBtrbJ+neup1EmYhzMWYxlpeh6TPiHXGC/ff/9991J77bsKP9Qscb
VKbsrgwD4ZfV2tzBT/sn4W54TStvurWMcstqITolJi5aDDa6qV+UrxGk4XsxWEKF
VHjLwOE1NsbRDsTzlj9WL/L8IoFj8xh53D5QtgLeE+LyzsqUnFOHMwiHWY0OqWnw
x97tudt/3qSQGnCInNjsdhEoRyAhjADX+F+IN5p94UwEhUHDmUcpt67I2GulfDXV
bB+1BBrLC8n+hzkOTrZte6p/JiZmctQxvL/WvkAqxdmAqmOVWUS5p7kfhEKrdpqH
D7X85IIrETu/oThR+8q0dLDG5bxGosz4nfCxKAT6VejXHNjCnfjqut8/NI/QmEhD
Lwaj5dTdRsPp51V89+AgL0EyjyYr18a5Ag0EYK6WGgEQAO9Ok+3TLFJog4tQaj9W
rzIK9ExNObB9897CHLmX0vn4HaJMKrRQV+G67lvFI4LC74LkgDamOkjmJtL6W4op
qSJkEEdd5X0kJK40zY5ZvVpotLgZU8t1gKlRNcAgnDh53aPWq6CcYk8+EgVmFFMZ
+e4AoYU/3wuqCIvTX8Xu5eGiG5aOuVf7JTjpMdnDDbPGkmvSsrSklmCRZPtKHTSt
IDBZdWLtXbUCx296Nb8rFLIxSENJOUiQmvY1EpN1104bmblJeXwqVc29VBw5J7zZ
lgl98vUWwrgGjspIeUnG8Voo8AQK+ZeC5SJd3fflTp4AS97Wyp1rjoutiTGkVVDG
QUvmdQtED+osQNrjYMGXPayusvsR0mqly8fN8wVMwuGeHVuI29ZD2SwpXLe50GGT
UegLvgF++aIY8NCvyU6xKb0vtuNVF+5sp0B6bb0ha94pQpvMdJd14+BSdKt4ZA2c
WEMeZQfyzAkFsePO9P/A0IHixm9xsNSIcZQSRQ2lMl9pYidX7j2g4KA1oUBomJhz
PAwJJisHbdYgOQ+lX6wv/NP6zac3SGpT0aOGlctk3MwydVaK1o8CR7G+Nq8lGoV1
V8f1r0VoJGWb/NI7Yskzd3C/oRLhHxCzJFMQsv/xhqXz2CrOrQlxAN8WFtFq6jvm
GSlO99lP1g+DBQroh1e5XgUrABEBAAGJAjYEGAEIACAWIQSZ8Uv+O/yvYPdXRIZ0
HR3z/M+PRQUCYK6WGgIbDAAKCRB0HR3z/M+PRSNQD/9+1Bi+nlp+u7UhxFKY8WK1
fr6WQNn9vtSa7oKUTqBvxSfoJ4W+1Y3gksR7qLzzXcb/jm0YmUqPWlTI/tQZTys9
9ynyETd+CwbJCFrR9+z9Rco5KW1UzZ8ZdzyvnL91abwSciSAWi08uljHReCdMV6v
tT0/w7CFZ1IRGUHeUA6hyFGKJfUjIgPR4qn0yOtVuzJuD6rcdUy8Tha7euNXTBrE
dLz9ycS2+N1jJpcFkUOWkTngCwqjUenzcQwF4uLTqwhKAHT1uwokOJKUYwqosy9z
hTgO4bosWcNIK9OCJyu4JH3p+AWJyBJgLbdvFQY/pImwZyvA47IPaXztlABoXh3D
KH3XXijAzCJOlC1GZYGB3sf3x2Tj4EO5YqKOAYZstcfbhxfPyygkd6OZhDTAkKzQ
agaZzLp9OJKnhnFJHhuaBQDM4Tx/yO6S1zdHyr90E8Cz/HQ8FCeCcA32ttF2E99v
NqCgPEqLSQsBa+TEwh5Dq5FubrOVfdnDCLco7Nm4DN/O0y6b9CUJJ6kPqcTWuVkz
oh6q8Qcx6+E0KUMiDR2+zwomGI+DBoBDdC6CGFkt2kUBOh5kk9z4MEVLlIqcXAgt
DOZuq8KHsK2PpSQ2aaWo5U9KviQMUik4uIC5wJkwUjcikSobOW9Zf9zWQ0/4RA9t
f8LDgcI77WYxILsl8jAU3w==
=bmim
-----END PGP PUBLIC KEY BLOCK-----
`

func validateChecksumProvider(providerPath string, checksumPath string) error {
	sha256sum, err := sha256File(providerPath)
	if err != nil {
		return err
	}
	f, err := os.Open(checksumPath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		split := strings.Split(scanner.Text(), "  ")
		if len(split) != 2 {
			return fmt.Errorf("checksum file in incorrect format")
		}
		if strings.Contains(split[1], runtime.GOOS) {
			if split[0] == sha256sum {
				return nil
			}
			return fmt.Errorf("provider checksum invalid expected %s got %s", split[1], sha256sum)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return fmt.Errorf("didn't find provider checksum vaildation for %s", providerPath)
}

func validateFile(targetPath string, signaturePath string) error {
	keys := strings.Join([]string{cloudQueryPublicKey, gennadySpbPublicKey}, "\n")
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(keys))
	if err != nil {
		return err
	}

	target, err := os.Open(targetPath)
	if err != nil {
		return err
	}
	defer target.Close()

	signature, err := os.Open(signaturePath)
	if err != nil {
		return err
	}
	defer signature.Close()

	_, err = openpgp.CheckDetachedSignature(keyring, target, signature)
	if err != nil {
		return err
	}

	return nil
}

func sha256File(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), err
}
