To deploy your web app on Render, follow these steps:

Set up Postgres Database

1. Create PostgreSQL database
2. Add following configuration settings:
	•	Database: mobile_market
	•	Username: mobile_market_user
3. Create the DB and get Internal Database URL from dashboard. 



Web application deployment

1. Create a web service on Render.
2. Configure the GitHub repository (https://github.com/KSburna/Database-project) with Render.
3. Configure the branch from which you need to pull the code. (release/1.0.0)
4. Add the following deployment settings to the created web service on Render:
	Build Command: pip install -r requirements.txt
	Start Command: python app.py

5. Add following environment variables,
	•	CONFIG_MODE=production
	•	PRODUCTION_DATABASE_URL=postgresql://mobile_market_user:ZFQTcNAfKy70wm5bDZS3RO9mSUHlBp2f@dpg-cphjv5m3e1ms73da2he0-a/mobile_market
Note: PRODUCTION_DATABASE_URL should be the Internal Database URL of created Postgres Database.

By following these instructions, you'll successfully deploy and access your web app on Render.com.

Link to the deployed web app: https://database-project-utug.onrender.com