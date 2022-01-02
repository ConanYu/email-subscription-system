docker_build:
	docker build -t goodguy-email .

docker_run:
	docker run -p 9853:9853 -dit goodguy-email python3 app.py
