gen-tests: docker-compose.yml
	docker-compose build
	docker-compose up

docker-compose.yml: template.j2 data.yml
	jinja2 template.j2 data.yml -o docker-compose.yml

.PHONY: gen-tests clean

clean:
	rm -rf ecdsa-eddsa/output
	rm -rf ecdsa-rsapss/output
	rm -rf eddsa-ecdsa/output
	rm -rf eddsa-rsapss/output
	rm -rf rsapss-ecdsa/output
	rm -rf rsarsae-eddsa/output
