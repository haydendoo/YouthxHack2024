import joblib
import string
from nltk.corpus import stopwords
import os

nb_model = joblib.load("models/emailsms_phish/model.pkl")
vect = joblib.load("models/emailsms_phish/vectorizer.pkl")
tfidf_transformer = joblib.load("models/emailsms_phish/tfidf_transformer.pkl")

def text_process(mess):
    STOPWORDS = stopwords.words('english') + ['u', 'ü', 'ur', '4', '2', 'im', 'dont', 'doin', 'ure']
    nopunc = [char for char in mess if char not in string.punctuation]
    nopunc = ''.join(nopunc)
    return ' '.join([word for word in nopunc.split() if word.lower() not in STOPWORDS])

def is_emailsms_phishing(msg):
    new_message_processed = [text_process(msg)]

    new_message_dtm = vect.transform(new_message_processed)
    new_message_tfidf = tfidf_transformer.transform(new_message_dtm)

    predicted_label = nb_model.predict(new_message_tfidf)

    return predicted_label[0] == 1