## 1. XSS Payload Types
	Reflected
	DOM
	Stored
## 2. Success Cretiria
	Observalbe State change
		The payloads does not need to retrieve the cookies, data or something else.
		Success is determined by observalbe state change or page changed,DOM mutation or updated state marker.
```Example paylaod
 <img src=x onerror="document.getElementById('lab-success-marker').textContent='success'">
 
 <img src=x onerror="document.body.dataset.xssState='success'">

```
## 3.  How we test the payload
	1. Enable the defenses one by one: We test each payload with each defenses(Only the defenses that related to the current payload; eg. We don't need to test the DOM sanitizer with a reflected XSS payload)
	2. After testing the defenses one by one, we test each payload layer by layer. Open each layer and test it. 
	3. After we done these tests, if we still have time or need more contents. We can test the mitigations. Eg. All these session security flags, cookie security flags, all these used for mitgate the effect.
	