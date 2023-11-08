#define NOMINMAX

#include <cmath>
#include <limits>
#include <map>
#include <stdint.h>

#include "ml_model.h"
#include "data.h"

namespace PacketAnalyzer
{

	KNN::KNN(int val)
	{
		k = val;
		neighbors = nullptr;
		trainingData = nullptr;
		testData = nullptr;
		validationData = nullptr;
	}

	KNN::KNN()
	{
		k = 3; // Default value for k
		neighbors = nullptr;
		trainingData = nullptr;
		testData = nullptr;
		validationData = nullptr;
	}

	KNN::~KNN()
	{
		// Cleaning up
	}

	template<class Archive>
	void KNN::serialize(Archive& ar, const unsigned int version)
	{
		ar& k;
		ar& neighbors;
		ar& trainingData;
		ar& testData;
		ar& validationData;
	}

	// save KNN instance
	void KNN::SaveKNN(std::string& fileName)
	{
		std::ofstream ofs(fileName);
		boost::archive::text_oarchive oa(ofs);
		oa << *this;
	}

	// load the KNN instace
	void KNN::LoadKNN(std::string& fileName)
	{
		std::ifstream ifs(fileName);
		boost::archive::text_iarchive ia(ifs);
		ia >> *this;
	}

	void KNN::FindKNearest(std::shared_ptr<DataCollection::Data> queryPoint)
	{
		neighbors = std::make_shared<std::vector<std::shared_ptr<DataCollection::Data>>>();
		double min = std::numeric_limits<double>::max();

		for (int i = 0; i < k; i++) {
			int index = -1;
			for (int j = 0; j < trainingData->size(); j++) {
				double distance = CalculateDistance(queryPoint, trainingData->at(j), DistanceMetric::EUCLID);
				trainingData->at(j)->SetDistance(distance);

				if (distance < min) {
					min = distance;
					index = j;
				}
			}

			if (index != -1) {
				neighbors->push_back(trainingData->at(index));
				min = std::numeric_limits<double>::max();
			}
		}
	}

	void KNN::SetTrainingData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		trainingData = vect;
	}

	void KNN::SetTestData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		testData = vect;
	}

	void KNN::SetValidationData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		validationData = vect;
	}

	void KNN::SetK(int val) // change k without reloading the data
	{
		k = val;
	}

	std::string KNN::Predict() // return predicted class
	{
		std::map<std::string, int> classFreq;
		for (int i = 0; i < neighbors->size(); i++)
		{
			if (classFreq.find(neighbors->at(i)->GetLabel()) == classFreq.end())
			{
				classFreq[neighbors->at(i)->GetLabel()] = 1;
			}
			else
			{
				classFreq[neighbors->at(i)->GetLabel()]++;
			}
		}

		std::string best;
		int max = 0;

		for (auto kv : classFreq)
		{
			if (kv.second > max)
			{
				max = kv.second;
				best = kv.first;
			}
		}
		neighbors->clear();
		return best;
	}

	double KNN::CalculateDistance(std::shared_ptr<DataCollection::Data> queryPoint, std::shared_ptr<DataCollection::Data> input, DistanceMetric metric)
	{
		double distance = 0.0;
		if (queryPoint->GetFeatureVectorSize() != input->GetFeatureVectorSize())
		{
			std::cerr<<"Error: Vector Size mismatch\n";
			exit(1);
		}

		for (unsigned i = 0; i < queryPoint->GetFeatureVectorSize(); i++)
		{
			if (metric == DistanceMetric::EUCLID)
			{
				distance += pow(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i), 2);
			}
			else if(metric == DistanceMetric::MANHATTAN)
			{
				distance += abs(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i));
			}
		}

		if (metric == DistanceMetric::EUCLID)
		{
			distance = sqrt(distance);
		}
		
	}

	const std::vector<std::string>& KNN::GetTrueLabels() const
	{
		return trueLabels;
	}

	const std::vector<std::string>& KNN::GetPredictedLabels() const
	{
		return predictedLabels;
	}

	double KNN::ValidatePerformance()
	{
		double currentPerformance = 0;
		int count = 0;
		int dataIndex = 0;

		for (std::shared_ptr<DataCollection::Data> queryPoint : *validationData)
		{
			FindKNearest(queryPoint);
			std::string prediction = Predict();
			if (prediction == queryPoint->GetLabel())
			{
				count++;
			}
			dataIndex++;
			//printf("Current Performance = %.3f %%\n", ((double)count * 100.0 / ((double)dataIndex)));
		}
		currentPerformance = ((double)count * 100) / ((double)validationData->size());
		printf("Validation performance for k = %d = %.3f %%\n", k, ((double)count * 100.0 / ((double)validationData->size())));
		return currentPerformance;
	}

	double KNN::TestPerformance()
	{
		double currentPerformance = 0.0;
		int count = 0;
		
		// clear the lists to store the true predicted labels
		trueLabels.clear();
		predictedLabels.clear();

		for (std::shared_ptr<DataCollection::Data> queryPoint: *testData)
		{
			FindKNearest(queryPoint);
			std::string prediction = Predict();

			trueLabels.push_back(queryPoint->GetLabel());
			predictedLabels.push_back(prediction);
			if (prediction == queryPoint->GetLabel())
			{
				count++;
			}
		}
		currentPerformance = ((double)count * 100) / ((double)testData->size());
		printf("Test performance = %.3f %%\n", currentPerformance);
		return currentPerformance;
	}
}