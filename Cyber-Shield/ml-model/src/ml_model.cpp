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

	// for the packet structure
	void KNN::SavePacket(const DataCollection::Packet& packet, const std::string& fileName)
	{
		std::ofstream ofs(fileName);
		boost::archive::text_oarchive oa(ofs);
		oa << packet;
	}

	DataCollection::Packet KNN::LoadPacket(const std::string& fileName)
	{
		DataCollection::Packet packet;
		std::ifstream ifs(fileName);
		boost::archive::text_iarchive ia(ifs);
		ia >> packet;
		return packet;
	}

	void KNN::FindKNearest(std::shared_ptr<DataCollection::Data> queryPoint)
	{
		neighbors = std::make_shared<std::vector<std::shared_ptr<DataCollection::Data>>>();
		double min = std::numeric_limits<double>::max();
		double prevMin = min;
		int index = 0;

		for (int i = 0; i < k; i++)
		{
			if (i == 0)
			{
				for (int j = 0; j < trainingData->size(); j++)
				{
					double distance = CalculateDistance(queryPoint, trainingData->at(j));
					trainingData->at(j)->SetDistance(distance);
					if (distance < min)
					{
						min = distance;
						index = j;
					}
					neighbors->push_back(trainingData->at(index));
					prevMin = min;
					min = std::numeric_limits<double>::max();
				}
			}
			else
			{
				for (int j = 0; j < trainingData->size(); j++)
				{
					double distance = trainingData->at(j)->GetDistance();
					if (distance > prevMin && distance < min)
					{
						min = distance;
						index = j;
					}
				}
				neighbors->push_back(trainingData->at(index));
				prevMin = min;
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

	int KNN::Predict() // return predicted class
	{
		std::map<uint8_t, int> classFreq;
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

		int best = 0;
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

	double KNN::CalculateDistance(std::shared_ptr<DataCollection::Data> queryPoint, std::shared_ptr<DataCollection::Data> input)
	{
		double distance = 0.0;
		if (queryPoint->GetFeatureVectorSize() != input->GetFeatureVectorSize())
		{
			std::cerr<<"Error: Vector Size mismatch\n";
			exit(1);
		}

		#ifdef EUCLID
		for (unsigned i; i < queryPoint->GetFeatureVectorSize(); i++)
		{
			distance += pow(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i), 2);
			std::cout << "Distance: " << distance;
		}
		distance = sqrt(distance);
		return distance;
		#elif defined MANHATTAN
		// manhattan distance calculation
		double manhattanDistance = 0.0;
		for (unsigned i = 0; i < queryPoint->GetFeatureVectorSize(); i++)
		{
			manhattanDistance += abs(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i));
		}
		return manhattanDistance;

		else
			return -1.0
		#endif

	}

	double KNN::ValidatePerformance()
	{
		double currentPerformance = 0;
		int count = 0;
		int dataIndex = 0;

		for (std::shared_ptr<DataCollection::Data> queryPoint : *validationData)
		{
			FindKNearest(queryPoint);
			int prediction = Predict();
			if (prediction == queryPoint->GetLabel())
			{
				count++;
			}
			dataIndex++;
			printf("Current Performance = %.3f %%\n", ((double)count * 100.0 / ((double)dataIndex)));
		}
		currentPerformance = ((double)count * 100) / ((double)validationData->size());
		printf("Validation performance for k = %d = %.3f %%\n", k, ((double)count * 100.0 / ((double)validationData->size())));
		return currentPerformance;
	}

	double KNN::TestPerformance()
	{
		double currentPerformance = 0.0;
		int count = 0;

		for (std::shared_ptr<DataCollection::Data> queryPoint: *testData)
		{
			FindKNearest(queryPoint);
			int prediction = Predict();
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