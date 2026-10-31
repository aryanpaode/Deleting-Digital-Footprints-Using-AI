OPTIONAL DLIB VISUAL-IDENTITY MODELS
====================================

Visual matching is optional. The rest of the project runs normally without
these files.

To enable the image feature, place these two standard dlib model files in this
models folder:

1. shape_predictor_5_face_landmarks.dat
2. dlib_face_recognition_resnet_model_v1.dat

The code uses these default paths:

models/shape_predictor_5_face_landmarks.dat
models/dlib_face_recognition_resnet_model_v1.dat

You may instead set these in .env:

DLIB_SHAPE_PREDICTOR_PATH=<path to shape_predictor_5_face_landmarks.dat>
DLIB_FACE_RECOGNITION_MODEL_PATH=<path to dlib_face_recognition_resnet_model_v1.dat>

Important:
- Do not place the user's uploaded reference photo in this folder.
- The web app saves the uploaded reference image only in a temporary directory
  during the scan and deletes it automatically afterward.
- The face descriptor is held in memory and is not written to reports.
- Dlib Euclidean distance is not a probability/percentage. The default
  thresholds (Strong <= 0.50, Possible <= 0.60) are starting values and should
  be calibrated on a validation set before making research accuracy claims.
