#ifndef ML_MODEL_H
#define ML_MODEL_H

#include "data.h"

namespace PacketAnalyzer
{
	class KNN
	{
		int k;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> neighbors;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> trainingData;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> testData;
		std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> validationData;

	public:
		KNN(int);
		KNN();
		~KNN();

		// Data serialization
		template<class Archive>
		void serialize(Archive& ar, const unsigned int);
		void SaveKNN(std::string& fileName);
		void LoadKNN(std::string& fileName);

		void SavePacket(const DataCollection::Packet&, const std::string& fileName);
		DataCollection::Packet LoadPacket(const std::string& fileName);

		void FindKNearest(std::shared_ptr<DataCollection::Data> queryPoint);
		void SetTrainingData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect);
		void SetTestData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect);
		void SetValidationData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect);
		void SetK(int); // change k without reloading the data

		int Predict(); // return predicted class
		double CalculateDistance(std::shared_ptr<DataCollection::Data> queryPoint, std::shared_ptr<DataCollection::Data> input);
		double ValidatePerformance();
		double TestPerformance();

	};
}

#endif // !ML_MODEL_H

