#ifndef ML_MODEL_H
#define ML_MODEL_H

#include "data.h";

namespace PacketAnalyzer
{
	class KNN
	{
		int k;
		std::vector<DataCollection::Data*>* neighbors;
		std::vector<DataCollection::Data*>* trainingData;
		std::vector<DataCollection::Data*>* testData;
		std::vector<DataCollection::Data*>* validationData;

	public:
		KNN(int);
		KNN();
		~KNN();


		void FindKNearest(DataCollection::Data* queryPoint);
		void SetTrainingData(std::vector<DataCollection::Data*>* vect);
		void SetTestData(std::vector<DataCollection::Data*>* vect);
		void SetValidationData(std::vector<DataCollection::Data*>* vect);
		void SetK(int); // change k without reloading the data

		int Predict(); // return predicted class
		double CalculateDistance(DataCollection::Data* queryPoint, DataCollection::Data* input);
		double ValidatePerformance();
		double TestPerformance();

		// Add seriali functions to save and load the model
		void SaveModel(const std::string& fileName);
		void LoadModel(const std::string& fileName);

	};
}

#endif // !ML_MODEL_H

