# Oasis Bank: customer book (fictional)

Every person, IBAN, device and IP below is made up for the hackathon. Bank code 999 is
not a real UAE bank, and the IPs are from the RFC 5737 documentation range.
Regenerate with `python3 -m oasis.data.generate`.

| ID | Customer | City | Occupation | IBAN | Balance (AED) | Daily limit | Usual hours |
|---|---|---|---|---|---:|---:|---|
| C001 | Layla Haddad | Dubai | Product designer | `AE079990000000048207919` | 184,250.00 | 50,000 | 08:00 to 23:00 |
| C002 | Omar Al Nuaimi | Abu Dhabi | Civil engineer | `AE799990000000048215838` | 412,900.00 | 75,000 | 06:00 to 22:00 |
| C003 | Priya Raman | Dubai | Pharmacist | `AE549990000000048223757` | 63,120.00 | 25,000 | 07:00 to 22:00 |
| C004 | Daniel Okafor | Sharjah | Logistics manager | `AE299990000000048231676` | 97,480.00 | 30,000 | 07:00 to 23:00 |
| C005 | Mariam Saeed | Dubai | Retired teacher | `AE049990000000048239595` | 1,240,000.00 | 40,000 | 08:00 to 20:00 |
| C006 | Arjun Mehta | Dubai | Software engineer | `AE769990000000048247514` | 236,700.00 | 60,000 | 09:00 to 24:00 |
| C007 | Sofia Petrova | Abu Dhabi | Hotel manager | `AE519990000000048255433` | 151,330.00 | 40,000 | 07:00 to 23:00 |
| C008 | Yousef Karim | Ajman | Shop owner | `AE269990000000048263352` | 58,900.00 | 35,000 | 06:00 to 23:00 |
| C009 | Hana Kobayashi | Dubai | Architect | `AE989990000000048271271` | 322,060.00 | 60,000 | 08:00 to 23:00 |
| C010 | Khalid Mansour | Ras Al Khaimah | Pilot | `AE739990000000048279190` | 689,400.00 | 100,000 | any time |
| C011 | Grace Mwangi | Dubai | Nurse | `AE489990000000048287109` | 41,870.00 | 20,000 | 06:00 to 24:00 |
| C012 | Faisal Rahman | Abu Dhabi | Student | `AE239990000000048295028` | 8,640.00 | 5,000 | 10:00 to 24:00 |

## Partner

**PayLink payouts** (PayLink Technologies (fictional)), API key `pk_live_paylink_01`, settlement IBAN `AE379990000000048100000`,
balance AED 512,000. Normally pays out about AED 1,850 each,
7:00 to 21:00, from AS-PAYLINK-DXB.

## Saved payees

- **C001**: Priya Raman `AE549990000000048223757`; Sofia Petrova `AE519990000000048255433`; Dubai Properties LLC `AE039990000000048908234`
- **C002**: Khalid Mansour `AE739990000000048279190`; Priya Raman `AE549990000000048223757`; Abu Dhabi Properties LLC `AE479990000000048903659`
- **C003**: Grace Mwangi `AE489990000000048287109`; Faisal Rahman `AE239990000000048295028`; Dubai Properties LLC `AE679990000000048909119`
- **C004**: Yousef Karim `AE269990000000048263352`; Grace Mwangi `AE489990000000048287109`; Sharjah Properties LLC `AE489990000000048908976`
- **C005**: Hana Kobayashi `AE989990000000048271271`; Grace Mwangi `AE489990000000048287109`; Dubai Properties LLC `AE329990000000048907227`
- **C006**: Daniel Okafor `AE299990000000048231676`; Layla Haddad `AE079990000000048207919`; Dubai Properties LLC `AE699990000000048901323`
- **C007**: Omar Al Nuaimi `AE799990000000048215838`; Mariam Saeed `AE049990000000048239595`; Abu Dhabi Properties LLC `AE649990000000048901607`
- **C008**: Hana Kobayashi `AE989990000000048271271`; Layla Haddad `AE079990000000048207919`; Ajman Properties LLC `AE959990000000048908033`
- **C009**: Faisal Rahman `AE239990000000048295028`; Arjun Mehta `AE769990000000048247514`; Dubai Properties LLC `AE059990000000048903445`
- **C010**: Sofia Petrova `AE519990000000048255433`; Mariam Saeed `AE049990000000048239595`; Ras Al Khaimah Properties LLC `AE209990000000048905697`
- **C011**: Arjun Mehta `AE769990000000048247514`; Sofia Petrova `AE519990000000048255433`; Dubai Properties LLC `AE639990000000048908415`
- **C012**: Grace Mwangi `AE489990000000048287109`; Omar Al Nuaimi `AE799990000000048215838`; Abu Dhabi Properties LLC `AE329990000000048905578`

## Demo logins (fictional, for the attack scripts)

| ID | Password | Device |
|---|---|---|
| C001 | `oasis-layla-1037` | `dev-fb346f36` |
| C002 | `oasis-omar-1074` | `dev-39f48f9f` |
| C003 | `oasis-priya-1111` | `dev-45e2abed` |
| C004 | `oasis-daniel-1148` | `dev-bf46a813` |
| C005 | `oasis-mariam-1185` | `dev-d1ace13b` |
| C006 | `oasis-arjun-1222` | `dev-ed6eb2f3` |
| C007 | `oasis-sofia-1259` | `dev-d482097e` |
| C008 | `oasis-yousef-1296` | `dev-9bcc9b3a` |
| C009 | `oasis-hana-1333` | `dev-58cb79bb` |
| C010 | `oasis-khalid-1370` | `dev-66b08420` |
| C011 | `oasis-grace-1407` | `dev-4cfc9f26` |
| C012 | `oasis-faisal-1444` | `dev-8be7f932` |

## Last 10 statement lines per customer

### C001 Layla Haddad

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-15 17:18 | card_groceries | Lulu Hypermarket | -143.70 |
| 2026-11-15 17:07 | card_transport | Salik | -85.36 |
| 2026-11-15 20:04 | card_shopping | Decathlon | -1,331.35 |
| 2026-11-16 12:28 | card_transport | ADNOC Fuel | -120.35 |
| 2026-11-17 09:39 | card_groceries | Spinneys | -168.27 |
| 2026-11-17 19:48 | card_transport | ADNOC Fuel | -125.77 |
| 2026-11-18 14:08 | card_dining | Ravi Restaurant | -225.44 |
| 2026-11-19 19:16 | card_dining | Shake Shack | -161.48 |
| 2026-11-19 10:32 | card_transport | Careem | -118.35 |
| 2026-11-20 15:24 | card_dining | Ravi Restaurant | -237.29 |

### C002 Omar Al Nuaimi

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-17 07:46 | card_groceries | Union Coop | -194.36 |
| 2026-11-17 10:48 | card_transport | Salik | -121.59 |
| 2026-11-18 19:45 | card_groceries | Carrefour City | -388.99 |
| 2026-11-18 18:05 | card_dining | Tim Hortons | -37.09 |
| 2026-11-18 06:26 | card_transport | ADNOC Fuel | -78.08 |
| 2026-11-19 15:42 | card_groceries | Carrefour City | -217.61 |
| 2026-11-19 14:14 | card_dining | Al Mallah | -49.57 |
| 2026-11-20 08:34 | card_groceries | Lulu Hypermarket | -132.84 |
| 2026-11-20 08:33 | card_dining | Tim Hortons | -232.27 |
| 2026-11-20 14:02 | card_transport | Careem | -25.76 |

### C003 Priya Raman

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-14 17:22 | card_dining | Shake Shack | -194.27 |
| 2026-11-15 13:18 | card_transport | ADNOC Fuel | -22.43 |
| 2026-11-16 20:31 | card_transport | ADNOC Fuel | -105.67 |
| 2026-11-17 07:59 | card_transport | Careem | -83.49 |
| 2026-11-18 12:02 | card_dining | Shake Shack | -150.33 |
| 2026-11-18 11:51 | card_transport | ADNOC Fuel | -54.53 |
| 2026-11-18 15:06 | card_shopping | Amazon.ae | -209.31 |
| 2026-11-19 07:12 | card_groceries | Carrefour City | -353.25 |
| 2026-11-19 09:56 | card_shopping | Amazon.ae | -479.06 |
| 2026-11-20 10:55 | card_transport | RTA Nol top-up | -92.98 |

### C004 Daniel Okafor

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-15 08:49 | card_dining | Shake Shack | -143.57 |
| 2026-11-15 16:15 | card_transport | ADNOC Fuel | -94.19 |
| 2026-11-16 19:16 | card_transport | ADNOC Fuel | -53.27 |
| 2026-11-17 10:22 | card_transport | ADNOC Fuel | -107.85 |
| 2026-11-17 15:30 | card_shopping | Decathlon | -922.59 |
| 2026-11-18 11:09 | card_groceries | Spinneys | -230.41 |
| 2026-11-18 14:22 | card_transport | RTA Nol top-up | -103.38 |
| 2026-11-18 14:32 | card_shopping | Amazon.ae | -479.16 |
| 2026-11-20 18:21 | card_groceries | Spinneys | -117.85 |
| 2026-11-20 22:31 | card_shopping | Amazon.ae | -1,109.90 |

### C005 Mariam Saeed

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-14 19:27 | card_transport | ADNOC Fuel | -27.62 |
| 2026-11-14 09:36 | transfer_out | Grace Mwangi | -670.00 |
| 2026-11-15 15:50 | card_groceries | Lulu Hypermarket | -239.00 |
| 2026-11-16 14:31 | card_transport | Careem | -72.21 |
| 2026-11-17 16:48 | card_groceries | Carrefour City | -167.88 |
| 2026-11-17 08:39 | card_transport | ADNOC Fuel | -10.85 |
| 2026-11-17 16:01 | card_shopping | IKEA | -312.85 |
| 2026-11-18 10:54 | card_groceries | Lulu Hypermarket | -33.63 |
| 2026-11-18 10:49 | card_transport | ADNOC Fuel | -82.61 |
| 2026-11-19 08:11 | card_dining | Al Mallah | -163.30 |

### C006 Arjun Mehta

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-13 17:21 | card_transport | Careem | -68.91 |
| 2026-11-14 23:27 | card_groceries | Spinneys | -443.88 |
| 2026-11-15 16:45 | card_groceries | Union Coop | -502.91 |
| 2026-11-16 10:53 | card_groceries | Spinneys | -490.64 |
| 2026-11-17 14:33 | card_groceries | Carrefour City | -83.31 |
| 2026-11-17 11:12 | card_dining | Shake Shack | -223.20 |
| 2026-11-17 14:47 | card_transport | RTA Nol top-up | -113.14 |
| 2026-11-19 10:45 | card_groceries | Lulu Hypermarket | -359.80 |
| 2026-11-19 20:32 | card_dining | Tim Hortons | -53.20 |
| 2026-11-20 21:58 | card_dining | Ravi Restaurant | -224.44 |

### C007 Sofia Petrova

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-14 15:52 | card_groceries | Union Coop | -407.94 |
| 2026-11-14 19:29 | card_dining | Ravi Restaurant | -175.26 |
| 2026-11-14 11:13 | card_transport | RTA Nol top-up | -17.75 |
| 2026-11-15 17:48 | card_dining | Shake Shack | -123.64 |
| 2026-11-16 18:29 | card_groceries | Spinneys | -344.16 |
| 2026-11-16 13:43 | card_transport | ADNOC Fuel | -71.69 |
| 2026-11-18 09:31 | card_transport | ADNOC Fuel | -86.45 |
| 2026-11-19 22:39 | card_groceries | Union Coop | -410.59 |
| 2026-11-20 12:26 | card_dining | Ravi Restaurant | -137.29 |
| 2026-11-20 12:05 | card_shopping | IKEA | -199.82 |

### C008 Yousef Karim

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-16 07:16 | card_dining | Al Mallah | -67.19 |
| 2026-11-17 20:24 | card_dining | Tim Hortons | -134.18 |
| 2026-11-17 06:04 | card_shopping | Noon | -201.85 |
| 2026-11-18 19:13 | card_dining | Tim Hortons | -59.83 |
| 2026-11-18 06:02 | card_transport | ADNOC Fuel | -97.47 |
| 2026-11-18 08:35 | card_shopping | Amazon.ae | -1,084.82 |
| 2026-11-19 16:15 | card_groceries | Union Coop | -283.52 |
| 2026-11-19 07:16 | card_dining | Ravi Restaurant | -40.17 |
| 2026-11-19 12:44 | card_transport | Careem | -50.61 |
| 2026-11-20 18:58 | card_dining | Shake Shack | -69.97 |

### C009 Hana Kobayashi

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-16 19:12 | card_groceries | Spinneys | -424.45 |
| 2026-11-16 16:35 | card_dining | Ravi Restaurant | -301.90 |
| 2026-11-17 11:24 | card_groceries | Spinneys | -203.71 |
| 2026-11-17 16:52 | card_dining | Ravi Restaurant | -149.92 |
| 2026-11-17 15:52 | card_transport | Careem | -72.58 |
| 2026-11-18 19:54 | card_groceries | Carrefour City | -193.42 |
| 2026-11-19 09:26 | card_transport | ADNOC Fuel | -35.57 |
| 2026-11-20 21:50 | card_groceries | Lulu Hypermarket | -292.66 |
| 2026-11-20 13:22 | card_dining | Tim Hortons | -315.90 |
| 2026-11-20 13:50 | card_transport | Careem | -91.77 |

### C010 Khalid Mansour

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-15 23:07 | card_transport | RTA Nol top-up | -47.62 |
| 2026-11-16 13:03 | card_groceries | Lulu Hypermarket | -542.32 |
| 2026-11-16 08:20 | card_transport | Careem | -135.59 |
| 2026-11-18 01:19 | card_groceries | Lulu Hypermarket | -478.14 |
| 2026-11-18 16:23 | transfer_out | Mariam Saeed | -1,150.00 |
| 2026-11-19 14:44 | card_transport | Careem | -155.73 |
| 2026-11-19 04:52 | card_shopping | Decathlon | -1,768.12 |
| 2026-11-20 02:52 | card_groceries | Lulu Hypermarket | -442.65 |
| 2026-11-20 23:08 | card_dining | Ravi Restaurant | -206.05 |
| 2026-11-20 21:22 | card_transport | ADNOC Fuel | -162.30 |

### C011 Grace Mwangi

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-15 23:23 | card_transport | Careem | -90.59 |
| 2026-11-15 07:19 | transfer_out | Arjun Mehta | -730.00 |
| 2026-11-16 22:33 | card_groceries | Carrefour City | -285.69 |
| 2026-11-17 19:17 | card_groceries | Carrefour City | -220.73 |
| 2026-11-17 14:39 | card_dining | Shake Shack | -199.42 |
| 2026-11-17 12:37 | card_transport | Salik | -18.88 |
| 2026-11-18 07:23 | card_groceries | Lulu Hypermarket | -269.75 |
| 2026-11-18 16:42 | card_transport | RTA Nol top-up | -75.18 |
| 2026-11-19 10:11 | card_transport | Careem | -81.96 |
| 2026-11-20 12:17 | card_transport | ADNOC Fuel | -46.15 |

### C012 Faisal Rahman

| Date | Type | Counterparty | Amount (AED) |
|---|---|---|---:|
| 2026-11-15 22:02 | card_shopping | IKEA | -128.71 |
| 2026-11-16 18:18 | card_groceries | Lulu Hypermarket | -34.55 |
| 2026-11-17 10:51 | card_groceries | Spinneys | -87.78 |
| 2026-11-18 12:44 | card_dining | Shake Shack | -24.81 |
| 2026-11-18 20:16 | card_transport | RTA Nol top-up | -28.60 |
| 2026-11-19 17:56 | card_groceries | Spinneys | -157.01 |
| 2026-11-19 12:29 | card_dining | Tim Hortons | -96.48 |
| 2026-11-19 10:23 | transfer_out | Grace Mwangi | -170.00 |
| 2026-11-20 12:02 | card_dining | Tim Hortons | -97.36 |
| 2026-11-20 23:00 | card_shopping | Amazon.ae | -31.50 |

Full history: 1,920 transactions over 90 days in `customers.json`.
