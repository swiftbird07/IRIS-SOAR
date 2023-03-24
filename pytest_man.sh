# Start pytest manually (withoud IDE) with the correct environment
export $(cat .env | xargs)
pytest tests -s
