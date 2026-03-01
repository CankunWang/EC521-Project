## 1. Problem Statement
### 1.1 Background
	Modern applications always deploy multiple defensive layers(HTML Escaping,cookie flags, CSP, hardcoding.... )
	However, most of the applications always only deploy limited numbers of restrictions with different combinations.
	The real world effectiveness and interaction between these defenses are often unclear.
### 1.2 Questions
###### 1.2.1 Is simple defenses enough?
###### 1.2.2 What are the common defenses combinations? How is the effect?
###### 1.2.3 Which defenses stop the execution of XSS?
###### 1.2.4 Which defenses only minimize the effectiveness of XSS?
###### 1.2.5 Is there are trade off?
## 3. Objectives
3.1 Build a dockerized web environment that can be used to test for different configuration and XSS payload
3.2 Achieved multi layer XSS defenses in dockerized web environment
3.3 Test for Non-persistent, persistent and DOM XSS payload
3.4 Measure the effectiveness of different defenses combination
## 4. System Design
#### 4.1 Experimental Environment(dockerized web application)
#### 4.2 Defenses layers
##### 4.2.1 Layer 1(Input&Output handling)
	Context aware encoding
	HTML escaping
	Template auto-escaping
	Allowlist validation
##### 4.2.2 Layer2 (Browser Enforcement)
	Content security policy(CSP)
	DOM api restriction
	Trusted Type
##### 4.2.3 Layer3 (Session Protection)
	Cookie httponly
	same site policy
	same origin policy
	Cookie secure
##### 4.2.4 Layer4 (Architectural Controls)
	Framework auto-escaping
	Avoid Inner HTML
	Security headers baseline
## 5. Methodology
#### 5.1 Attack categories
	Reflected XSS
	Stored XSS
	DOM-based XSS
#### 5.2 Evaluation metrics
	Success rate
	Script execution success
	effectiveness(data exfiltration)
	blocking rate
	Defense complexity
	Questions: 
		Does implementation follow contextual encoding?
		Is CSP strict-dynamic?
		Are cookies properly flagged?
		Is inline script allowed?
## 6. Model
	Level 1: Basic encoding
	Level 2: Encoding + CSP
	Level 3: Full contextual encoding + Strict CSP
	Level 4: Trusted Types + Architectural redesign
## 7. Team members
	Cankun Wang
	Krista Smith
	Thinh Phuc Nguyen
	Fuyang Chen