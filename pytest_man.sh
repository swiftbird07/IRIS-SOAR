# Start pytest manually (withoud IDE) with the correct environment
export $(cat .env | xargs)
python3 -m pytest -s
