#ifndef ML_MODEL_H
#define ML_MODEL_H

#include "data.h"

namespace PacketAnalyzer
{
	enum class DistanceMetric
	{
		EUCLID,
		MANHATTAN
	};

	class KNN
	{
		int k;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> neighbors;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> trainingData;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> testData;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> validationData;

		std::vector<std::string> trueLabels;       // Store the true labels for test data
		std::vector<std::string> predictedLabels;  // Store the predicted labels for test data

	public:
		KNN(int);
		KNN();
		~KNN();

		// Data serialization
		template<class Archive>
		void serialize(Archive& ar, const unsigned int);
		void SaveKNN(std::string& fileName);
		void LoadKNN(std::string& fileName);

		void FindKNearest(std::shared_ptr<DataCollection::Data> queryPoint);
		void SetTrainingData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect);
		void SetTestData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect);
		void SetValidationData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect);
		void SetK(int); // change k without reloading the data

		std::string Predict(); // return predicted class
		double CalculateDistance(std::shared_ptr<DataCollection::Data> queryPoint, std::shared_ptr<DataCollection::Data> input, DistanceMetric metric);
		double ValidatePerformance();
		double TestPerformance();

		const std::vector<std::string>& GetTrueLabels() const;

		const std::vector<std::string>& GetPredictedLabels() const;

	};
}

#endif // !ML_MODEL_H

