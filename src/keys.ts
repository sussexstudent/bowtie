import * as AWS from 'aws-sdk';
import * as SSM from 'aws-sdk/clients/ssm';

AWS.config.update({ region: "eu-west-1" });

const ssm = new SSM()

export const loadParams = async (names: string[]): Promise<Map<string, SSM.Parameter>> => {
    const query = {
        "Names": names,
        "WithDecryption": true
    }
    const res = await ssm.getParameters(query).promise()

    if (res.Parameters) {
        const map = res.Parameters.reduce((m, param) => {
            m.set(param.Name, param);
    
            return m;
        }, new Map())
    
        return map;
    }

    throw new Error('key access failed');
};
