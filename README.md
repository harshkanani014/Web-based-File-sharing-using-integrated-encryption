# WEB BASED FILE SHARING USING INTEGRATED ENCRYPTION

## STEP-1 : Install PostgreSQl with pgAdmin
### How to install PostgreSQL?
##### Download postgreSQL from following link and install 
##### https://www.enterprisedb.com/downloads/postgres-postgresql-downloads

## STEP-2 : Set Up Database 
##### Open PgAdmin and Create a database with related name in PgAdmin.

## STEP-3 : Clone this repository

## STEP-4 : Creating Virtual environment
##### Use following command to set up virtual environment
```py -m venv <env-name>```
##### Activate environment
```<env-name>\Scripts\activate.bat```

## STEP-5 Install requirements.txt
```pip install -r requirements.txt```

## STEP-6 : Go to erp_backend/settings.py
##### Replace database_name, database_user and database_password in following code

```DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'your-database-name',
        'USER': 'your-user-name',
        'PASSWORD': 'your-password',
        'HOST': 'localhost'
    }
} 
```



## STEP-7 : Run following commands
```python manage.py makemigrations```

```python manage.py migrate```

```python manage.py runserver```

#### Hurrah your website is running


## Thank you



