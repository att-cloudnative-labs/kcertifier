# Kcertifier

---

<p align="center">
  <a href="https://goreportcard.com/report/github.com/att-cloudnative-labs/kcertifier" alt="Go Report Card">
    <img src="https://goreportcard.com/badge/github.com/att-cloudnative-labs/kcertifier">
  </a>
</p>
<p align="center">
    <a href="https://github.com/att-cloudnative-labs/kcertifier/graphs/contributors" alt="Contributors">
		<img src="https://img.shields.io/github/contributors/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/commits/master" alt="Commits">
		<img src="https://img.shields.io/github/commit-activity/m/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/pulls" alt="Open pull requests">
		<img src="https://img.shields.io/github/issues-pr-raw/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/pulls" alt="Closed pull requests">
    	<img src="https://img.shields.io/github/issues-pr-closed-raw/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/issues" alt="Issues">
		<img src="https://img.shields.io/github/issues-raw/att-cloudnative-labs/kcertifier.svg">
	</a>
	</p>
<p align="center">
	<a href="https://github.com/att-cloudnative-labs/kcertifier/stargazers" alt="Stars">
		<img src="https://img.shields.io/github/stars/att-cloudnative-labs/kcertifier.svg?style=social">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/watchers" alt="Watchers">
		<img src="https://img.shields.io/github/watchers/att-cloudnative-labs/kcertifier.svg?style=social">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/network/members" alt="Forks">
		<img src="https://img.shields.io/github/forks/att-cloudnative-labs/kcertifier.svg?style=social">
	</a>
</p>

----

Kcertifier is an daemon that automatically makes a wildcard SSL certificate/key in each namespace signed by the Kubernetes CA (certificatesigningrequest api). The certificate in each namespace will have the common name, "*.namespacename.svc.cluster.local". For a namespace to be eligible, it must have the annotation, kcertifier.atteg.com/enabled="true". This daemon should only be run in a secure cluster where any deployed application is trusted to present a certificate signed by the kubernetes root CA. 